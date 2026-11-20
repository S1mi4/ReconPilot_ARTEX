package audit;

import java.util.Map;

// Context only: inventoried as test, never executed by the Go regression.
public final class NoteStoreTest {
    public static void ownershipControl() {
        NoteStore.Note note = new NoteStore.Note("alice", "private");
        Map<String, NoteStore.Note> notes = Map.of("n1", note);
        if (NoteStore.readOwned(notes, "mallory", "n1") != null
                || NoteStore.readOwned(notes, "alice", "n1") != note) {
            throw new AssertionError("ownership control failed");
        }
    }
}
