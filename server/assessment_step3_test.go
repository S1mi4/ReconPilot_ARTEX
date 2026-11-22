package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestStep3MixedLanguageSharedLibMultiInstanceAndConfigConflict(t *testing.T) {
	s, _, token := step2TestServer(t)
	h := s.Handler()

	// 1. Create dynamic whitebox draft with multiple runtime instances & credential refs.
	createRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":            "step3-mixed-profile",
		"description":     "混合语言与多实例画像验收",
		"assessment_mode": true,
		"assessment_config": map[string]any{
			"execution_mode":    "dynamic",
			"business_overview": "订单与账单多语言微服务平台",
			"business_focus":    []string{"订单权限校验", "账单扣款"},
			"environments": []map[string]any{
				{"name": "staging-api", "url": "http://api.staging.test:8080", "is_default": true},
				{"name": "staging-admin", "url": "http://admin.staging.test:8081"},
			},
			"env_access": map[string]any{"mode": "vpn", "notes": "测试内网网关"},
			"identities": []map[string]any{
				{"role": "buyer", "username": "u_buyer", "credential_ref": "vault://staging/buyer", "auth_type": "jwt"},
				{"role": "ops_admin", "username": "u_ops", "credential_ref": "vault://staging/ops", "auth_type": "session"},
			},
			"scope_notes": "仅测试 staging-api 与 staging-admin",
		},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create draft failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var taskObj TaskDTO
	if err := json.Unmarshal(createRec.Body.Bytes(), &taskObj); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })

	// 2. Upload mixed-language monorepo: Java service, Java shared lib, Python service, C shared library,
	//    conflicting application.yml vs application-prod.yml, secret value that must never leak, and docker-compose.yml.
	uploadRec := step2UploadCodebase(t, h, token, taskObj.ID, "directory", []codebaseTestFile{
		{
			path: "monorepo/pom.xml",
			data: []byte(`<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>mono</artifactId><packaging>pom</packaging><modules><module>order-service</module><module>common-auth</module></modules></project>`),
		},
		{
			path: "monorepo/order-service/pom.xml",
			data: []byte(`<project><artifactId>order-service</artifactId><packaging>jar</packaging><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`),
		},
		{
			path: "monorepo/order-service/src/main/java/com/example/order/OrderController.java",
			data: []byte("package com.example.order;\n@RestController\n@RequestMapping(\"/api\")\npublic class OrderController {\n  @GetMapping(\"/orders\")\n  public String listOrders() { return \"ok\"; }\n}\n"),
		},
		{
			path: "monorepo/order-service/src/main/java/com/example/order/SecurityConfig.java",
			data: []byte("package com.example.order;\npublic class SecurityConfig {\n  SecurityFilterChain filterChain() { return null; }\n}\n"),
		},
		{
			path: "monorepo/order-service/src/main/resources/application.yml",
			data: []byte("server:\n  port: 8080\nsecurity:\n  csrf:\n    enabled: true\nspring:\n  datasource:\n    url: jdbc:postgresql://db.internal:5432/orders\n    password: SuperSecret123\n"),
		},
		{
			path: "monorepo/order-service/src/main/resources/application-prod.yml",
			data: []byte("server:\n  port: 9090\nsecurity:\n  csrf:\n    enabled: false\n"),
		},
		{
			path: "monorepo/common-auth/pom.xml",
			data: []byte(`<project><artifactId>common-auth</artifactId><packaging>jar</packaging></project>`),
		},
		{
			path: "monorepo/common-auth/src/main/java/com/example/auth/TokenValidator.java",
			data: []byte("package com.example.auth;\npublic class TokenValidator {\n  public boolean verify(String t) { return Jwts.parser() != null; }\n}\n"),
		},
		{
			path: "monorepo/billing-py/pyproject.toml",
			data: []byte("[project]\nname = \"billing-py\"\ndependencies = [\"fastapi\", \"uvicorn\"]\n"),
		},
		{
			path: "monorepo/billing-py/app.py",
			data: []byte("from fastapi import FastAPI, Depends\napp = FastAPI()\n@app.post(\"/billing/charge\")\ndef charge(user=Depends(require_auth)):\n    return {\"ok\": True}\n"),
		},
		{
			path: "monorepo/native-crypto/CMakeLists.txt",
			data: []byte("cmake_minimum_required(VERSION 3.20)\nproject(native_crypto C)\nadd_library(crypto_core STATIC crypto.c)\n"),
		},
		{
			path: "monorepo/native-crypto/crypto.h",
			data: []byte("#ifndef CRYPTO_H\n#define CRYPTO_H\nint verify_hmac(const char *buf);\n#endif\n"),
		},
		{
			path: "monorepo/native-crypto/crypto.c",
			data: []byte("#include \"crypto.h\"\nint verify_hmac(const char *buf) { return buf != 0; }\n"),
		},
		{
			path: "monorepo/docker-compose.yml",
			data: []byte("services:\n  order-service:\n    build: ./order-service\n    ports:\n      - \"8080:8080\"\n  admin-gateway:\n    image: nginx:alpine\n    ports:\n      - \"8081:80\"\n"),
		},
	})
	if uploadRec.Code != http.StatusCreated {
		t.Fatalf("upload monorepo failed: %d %s", uploadRec.Code, uploadRec.Body.String())
	}

	// 3. Run material check & explicit start.
	checkRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/material-check", nil)
	if checkRec.Code != http.StatusOK {
		t.Fatalf("material-check failed: %d %s", checkRec.Code, checkRec.Body.String())
	}
	startRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/start", map[string]any{"source_acknowledged": true})
	if startRec.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", startRec.Code, startRec.Body.String())
	}

	// 4. Synchronously rebuild profile so all deterministic extraction & assertions are settled.
	rebuildRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/rebuild", map[string]any{"enable_agent": false})
	if rebuildRec.Code != http.StatusOK {
		t.Fatalf("profile rebuild failed: %d %s", rebuildRec.Code, rebuildRec.Body.String())
	}

	getRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+taskObj.ID+"/profile", nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get profile failed: %d %s", getRec.Code, getRec.Body.String())
	}
	rawProfile := getRec.Body.String()
	if strings.Contains(rawProfile, "SuperSecret123") {
		t.Fatalf("plaintext secret SuperSecret123 leaked in profile response")
	}

	var prof AssessmentProfileResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &prof); err != nil {
		t.Fatal(err)
	}
	if prof.Summary == nil || !prof.Summary.InitialProfileReady || prof.Round == nil || prof.Summary.ProfileVersion < 1 {
		t.Fatalf("expected ready profile with version >= 1, got summary=%+v round=%+v", prof.Summary, prof.Round)
	}
	for _, wantLang := range []string{"java", "python", "c"} {
		if !slices.Contains(prof.Summary.Languages, wantLang) {
			t.Fatalf("expected language %q in %v", wantLang, prof.Summary.Languages)
		}
	}

	hasEntity := func(etype, nameSubstr string) bool {
		for _, e := range prof.Entities {
			if e.EntityType == etype && strings.Contains(e.Name, nameSubstr) && !e.Gap {
				return true
			}
		}
		return false
	}
	if !hasEntity("service", "order-service") || !hasEntity("service", "billing-py") {
		t.Fatalf("missing expected deployable services in entities: %+v", prof.Entities)
	}
	if !hasEntity("shared_library", "common-auth") || !hasEntity("shared_library", "crypto_core") {
		t.Fatalf("missing expected shared libraries (common-auth, crypto_core) in entities: %+v", prof.Entities)
	}
	if !hasEntity("entry", "HTTP GET /api/orders") || !hasEntity("entry", "HTTP POST /billing/charge") {
		t.Fatalf("missing extracted Java/Python entries in entities: %+v", prof.Entities)
	}
	if !hasEntity("instance", "staging-api") || !hasEntity("instance", "staging-admin") {
		t.Fatalf("missing multiple runtime instances in entities: %+v", prof.Entities)
	}
	if !hasEntity("config", "application.yml") || !hasEntity("config", "application-prod.yml") || !hasEntity("config", "docker-compose.yml") {
		t.Fatalf("missing config entities: %+v", prof.Entities)
	}

	// Verify config conflicts (server_port 8080 vs 9090; csrf_protection enabled vs disabled) preserve BOTH rows.
	var portConflicts, csrfConflicts, secretRefs, unverifiedDeploys, unmappedAdmin int
	for _, c := range prof.Claims {
		if c.Subject == "service:order-service" && c.Relation == "server_port" && c.ConfirmationStatus == db.ClaimStatusConflicted {
			portConflicts++
		}
		if c.Subject == "service:order-service" && c.Relation == "csrf_protection" && c.ConfirmationStatus == db.ClaimStatusConflicted {
			csrfConflicts++
		}
		if c.Subject == "service:order-service" && c.Relation == "references_secret_config" && strings.Contains(c.ObjectValue, "password") {
			secretRefs++
		}
		if c.Subject == "service:order-service" && c.Relation == "deployed_to_instance" && c.ObjectValue == "instance:staging-api" {
			if c.ConfirmationStatus != db.ClaimStatusUnverified || c.SourceType == db.ClaimSourceRuntimeObservation {
				t.Fatalf("static code->deployment mapping must stay unverified static_extraction, got %+v", c)
			}
			unverifiedDeploys++
		}
		if c.Subject == "instance:staging-admin" && c.Relation == "code_deployment_mapping" && c.ConfirmationStatus == db.ClaimStatusUnknown {
			unmappedAdmin++
		}
	}
	if portConflicts != 2 || csrfConflicts != 2 {
		t.Fatalf("expected 2 conflicted port claims and 2 conflicted csrf claims, got port=%d csrf=%d", portConflicts, csrfConflicts)
	}
	if secretRefs == 0 || unverifiedDeploys == 0 || unmappedAdmin == 0 {
		t.Fatalf("expected secretRef(%d), unverifiedDeploy(%d), unmappedAdmin(%d) claims", secretRefs, unverifiedDeploys, unmappedAdmin)
	}
}

func TestStep3JavaBinaryArtifactAndUnreadableGap(t *testing.T) {
	s, _, token := step2TestServer(t)
	h := s.Handler()

	// Pretend JavaCodeDB probe is ready during Step-2 start gate.
	s.javaCodeDBProbe = func() taskJavaCodeDBConfig {
		return taskJavaCodeDBConfig{Ready: true, Version: "test-jcdb-21"}
	}

	// Build a binary-only JAR containing MANIFEST.MF, application.properties, valid .class, and a corrupted .class.
	jarBytes := buildTestZipBytes(t, map[string][]byte{
		"META-INF/MANIFEST.MF":                         []byte("Manifest-Version: 1.0\nStart-Class: com.example.RefundApp\nSpring-Boot-Version: 3.3.0\n"),
		"BOOT-INF/classes/application.properties":      []byte("server.port=8080\nspring.application.name=refund-svc\n"),
		"BOOT-INF/classes/com/example/RefundApp.class": validMinimalJavaClassBytes(),
		"BOOT-INF/classes/com/example/Corrupt.class":   []byte("not-a-valid-class-file"),
		"BOOT-INF/lib/jackson-databind-2.17.0.jar":     buildTestZipBytes(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\n")}),
	})

	createRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":            "step3-java-binary-profile",
		"description":     "Java 二进制与缺口画像验收",
		"assessment_mode": true,
		"assessment_config": map[string]any{
			"execution_mode": "offline",
		},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create draft failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var taskObj TaskDTO
	_ = json.Unmarshal(createRec.Body.Bytes(), &taskObj)
	t.Cleanup(func() { _, _ = s.m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })

	upRec := step2UploadCodebase(t, h, token, taskObj.ID, "artifact", []codebaseTestFile{
		{path: "refund-app.jar", data: jarBytes},
	})
	if upRec.Code != http.StatusCreated {
		t.Fatalf("upload jar failed: %d %s", upRec.Code, upRec.Body.String())
	}

	// Subcase A: JavaCodeDB profile probe returns decompiled application classes and web endpoints.
	s.javaCodeDBProfileProbe = func(_ context.Context, _ string, _ taskCodebaseVersion) (*javaBinaryProfileSummary, error) {
		return &javaBinaryProfileSummary{
			Available: true,
			ApplicationClasses: []javaBinaryClassSummary{
				{ClassName: "com.example.RefundController", Artifact: "refund-app.jar", Entry: "BOOT-INF/classes/com/example/RefundController.class", Application: true},
			},
			WebEndpoints: []javaBinaryEndpointSummary{
				{Method: "POST", Path: "/internal/refund", ClassName: "com.example.RefundController", MethodName: "refund", Artifact: "refund-app.jar", Entry: "BOOT-INF/classes/com/example/RefundController.class"},
			},
		}, nil
	}

	if rec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/material-check", nil); rec.Code != http.StatusOK {
		t.Fatalf("material-check failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/start", map[string]any{"source_acknowledged": true}); rec.Code != http.StatusOK {
		t.Fatalf("start failed: %d %s", rec.Code, rec.Body.String())
	}
	rebuildA := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/rebuild", map[string]any{"enable_agent": false})
	if rebuildA.Code != http.StatusOK {
		t.Fatalf("rebuild A failed: %d %s", rebuildA.Code, rebuildA.Body.String())
	}
	var profA AssessmentProfileResponse
	if err := json.Unmarshal(rebuildA.Body.Bytes(), &profA); err != nil {
		t.Fatal(err)
	}
	hasDecompiledEntry := false
	hasCorruptGap := false
	for _, e := range profA.Entities {
		if e.EntityType == "entry" && e.Name == "HTTP POST /internal/refund" && !e.Gap {
			hasDecompiledEntry = true
		}
		if e.Gap && strings.Contains(e.Name, "Corrupt.class") {
			hasCorruptGap = true
		}
	}
	if !hasDecompiledEntry {
		t.Fatalf("expected decompiled entry HTTP POST /internal/refund, got entities=%+v", profA.Entities)
	}
	if !hasCorruptGap {
		t.Fatalf("expected explicit gap for Corrupt.class, got entities=%+v", profA.Entities)
	}
	hasDecompiledEv := false
	for _, ev := range profA.EvidenceRefs {
		if ev.Kind == string(db.EvidenceDecompiled) && strings.Contains(ev.Reference, "RefundController.java") {
			hasDecompiledEv = true
		}
	}
	if !hasDecompiledEv {
		t.Fatalf("expected EvidenceDecompiled ref for RefundController, got %+v", profA.EvidenceRefs)
	}

	// Subcase B: JavaCodeDB becomes unavailable during profile rebuild -> explicit gap & unknown claim.
	s.javaCodeDBProfileProbe = func(_ context.Context, _ string, _ taskCodebaseVersion) (*javaBinaryProfileSummary, error) {
		return &javaBinaryProfileSummary{Available: false, UnavailableReason: "JavaCodeDB worker offline"}, nil
	}
	rebuildB := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/rebuild", map[string]any{"enable_agent": false})
	if rebuildB.Code != http.StatusOK {
		t.Fatalf("rebuild B failed: %d %s", rebuildB.Code, rebuildB.Body.String())
	}

	gapRec := httpJSON(t, h, token, http.MethodGet, "/api/tasks/"+taskObj.ID+"/profile?gap_only=true", nil)
	if gapRec.Code != http.StatusOK {
		t.Fatalf("gap_only query failed: %d %s", gapRec.Code, gapRec.Body.String())
	}
	var profGap AssessmentProfileResponse
	_ = json.Unmarshal(gapRec.Body.Bytes(), &profGap)
	hasJCDBGap := false
	for _, e := range profGap.Entities {
		if e.Gap && strings.Contains(e.Name, "JavaCodeDB") {
			hasJCDBGap = true
		}
	}
	if !hasJCDBGap {
		t.Fatalf("expected JavaCodeDB gap entity in gap_only response: %+v", profGap.Entities)
	}

	taskNum, _ := strconv.ParseInt(taskObj.ID, 10, 64)
	compRep, err := s.m.pg.AssessmentCompletionCheck(taskNum)
	if err != nil {
		t.Fatal(err)
	}
	if compRep.CanComplete || compRep.UnresolvedGaps == 0 {
		t.Fatalf("expected unresolved gaps to block completion: %+v", compRep)
	}
}

func TestStep3AgentToolsAndInferenceHonesty(t *testing.T) {
	s, _, token := step2TestServer(t)
	h := s.Handler()
	ctx := context.Background()

	createRec := httpJSON(t, h, token, http.MethodPost, "/api/tasks", map[string]any{
		"name":            "step3-agent-tools",
		"description":     "Agent 画像工具与推断诚实性校验",
		"assessment_mode": true,
		"assessment_config": map[string]any{
			"execution_mode": "offline",
		},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", createRec.Code, createRec.Body.String())
	}
	var taskObj TaskDTO
	_ = json.Unmarshal(createRec.Body.Bytes(), &taskObj)
	t.Cleanup(func() { _, _ = s.m.DeleteTask(taskObj.ID, DeleteTaskOptions{}) })

	upRec := step2UploadCodebase(t, h, token, taskObj.ID, "directory", []codebaseTestFile{
		{
			path: "svc/pom.xml",
			data: []byte(`<project><artifactId>order-service</artifactId><build><plugins><plugin><artifactId>spring-boot-maven-plugin</artifactId></plugin></plugins></build></project>`),
		},
		{
			path: "svc/src/main/java/com/example/OrderController.java",
			data: []byte("package com.example;\n@RestController\npublic class OrderController {\n  @GetMapping(\"/orders\")\n  public String list() { return \"ok\"; }\n}\n"),
		},
	})
	if upRec.Code != http.StatusCreated {
		t.Fatalf("upload failed: %d %s", upRec.Code, upRec.Body.String())
	}
	if rec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/material-check", nil); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if rec := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/start", map[string]any{"source_acknowledged": true}); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}

	// 1. rebuild_task_profile via orchestration tool.
	rebuildArgs, _ := json.Marshal(map[string]any{"task_id": taskObj.ID, "enable_agent": false})
	rebuildRes, err := s.toolRebuildTaskProfile().Call(ctx, rebuildArgs, nil)
	if err != nil || rebuildRes.IsError {
		t.Fatalf("rebuild_task_profile failed: err=%v res=%s", err, rebuildRes.Flatten())
	}

	// 2. record_task_profile_claim rejects runtime_observation impersonation & confirmed inference & secrets.
	badCases := []map[string]any{
		{
			"task_id": taskObj.ID, "subject": "service:order-service", "relation": "auth_required",
			"object_value": "false", "source_type": "runtime_observation",
			"evidence_kind": "code_range", "evidence_reference": "OrderController.java:1",
		},
		{
			"task_id": taskObj.ID, "subject": "service:order-service", "relation": "auth_required",
			"object_value": "true", "source_type": "model_inference", "confirmation_status": "confirmed",
			"evidence_kind": "code_range", "evidence_reference": "OrderController.java:1",
		},
		{
			"task_id": taskObj.ID, "subject": "service:order-service", "relation": "auth_mechanism",
			"object_value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			"source_type":  "model_inference", "confirmation_status": "unverified",
			"evidence_kind": "code_range", "evidence_reference": "OrderController.java:1",
		},
	}
	for i, tc := range badCases {
		raw, _ := json.Marshal(tc)
		res, _ := s.toolRecordTaskProfileClaim().Call(ctx, raw, nil)
		if !res.IsError {
			t.Fatalf("bad case %d expected tool error, got: %s", i, res.Flatten())
		}
	}

	// Valid model_inference claim succeeds and stays unverified.
	goodArgs, _ := json.Marshal(map[string]any{
		"task_id": taskObj.ID, "subject": "service:order-service", "relation": "auth_mechanism",
		"object_value": "jwt_likely", "source_type": "model_inference", "confirmation_status": "unverified",
		"evidence_kind": "code_range", "evidence_reference": "svc/src/main/java/com/example/OrderController.java:2",
	})
	goodRes, err := s.toolRecordTaskProfileClaim().Call(ctx, goodArgs, nil)
	if err != nil || goodRes.IsError || !strings.Contains(goodRes.Flatten(), `"model_inference"`) {
		t.Fatalf("expected valid model_inference claim to succeed: err=%v res=%s", err, goodRes.Flatten())
	}

	// 3. get_task_profile targeted slice.
	getArgs, _ := json.Marshal(map[string]any{
		"task_id": taskObj.ID, "subjects": []string{"service:order-service"}, "limit": 50,
	})
	getRes, err := s.toolGetTaskProfile().Call(ctx, getArgs, nil)
	if err != nil || getRes.IsError || !strings.Contains(getRes.Flatten(), `"profile_version"`) || !strings.Contains(getRes.Flatten(), `"jwt_likely"`) {
		t.Fatalf("get_task_profile slice unexpected: err=%v res=%s", err, getRes.Flatten())
	}

	// 4. HTTP POST /api/tasks/{id}/profile/claims enforcement.
	httpBad := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/claims", map[string]any{
		"subject":             "service:order-service",
		"relation":            "auth_required",
		"object_value":        "true",
		"source_type":         "model_inference",
		"confirmation_status": "confirmed",
		"evidence":            map[string]any{"kind": "code_range", "reference": "OrderController.java:4"},
	})
	if httpBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for confirmed model_inference via HTTP, got %d %s", httpBad.Code, httpBad.Body.String())
	}

	httpBadRuntime := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/claims", map[string]any{
		"subject":             "entry:HTTP GET /orders",
		"relation":            "auth_required",
		"object_value":        "false",
		"source_type":         "runtime_observation",
		"confirmation_status": "confirmed",
		"evidence":            map[string]any{"kind": "code_range", "reference": "OrderController.java:4"},
	})
	if httpBadRuntime.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for confirmed runtime_observation with code_range evidence, got %d %s", httpBadRuntime.Code, httpBadRuntime.Body.String())
	}

	httpGoodRuntime := httpJSON(t, h, token, http.MethodPost, "/api/tasks/"+taskObj.ID+"/profile/claims", map[string]any{
		"subject":             "entry:HTTP GET /orders",
		"relation":            "auth_required",
		"object_value":        "false",
		"source_type":         "runtime_observation",
		"confirmation_status": "confirmed",
		"environment":         "staging",
		"evidence":            map[string]any{"kind": "traffic", "reference": "traffic#200"},
	})
	if httpGoodRuntime.Code != http.StatusCreated {
		t.Fatalf("expected 201 for runtime_observation with traffic evidence, got %d %s", httpGoodRuntime.Code, httpGoodRuntime.Body.String())
	}
}
