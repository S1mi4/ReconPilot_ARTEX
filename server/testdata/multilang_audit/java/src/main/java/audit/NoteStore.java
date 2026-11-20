package audit;

import java.util.Map;

// Source-only audit fixture. No server or executable entry point.
public final class NoteStore {
    public static final class Note {
        public final String owner;
        public final String body;

        public Note(String owner, String body) {
            this.owner = owner;
            this.body = body;
        }
    }

    // The authenticated caller supplies principal; noteId is attacker-controlled.
    public static Note readUnchecked(Map<String, Note> notes, String principal, String noteId) {
        return notes.get(noteId); // JAVA-AUTHZ-READ: missing ownership check.
    }

    public static Note readOwned(Map<String, Note> notes, String principal, String noteId) {
        Note note = notes.get(noteId);
        if (note == null || !note.owner.equals(principal)) { // JAVA-AUTHZ-CONTROL
            return null;
        }
        return note;
    }
}
