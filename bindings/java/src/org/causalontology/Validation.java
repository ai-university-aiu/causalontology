package org.causalontology;

import java.util.List;

/**
 * The (ok, reasons) result pair used by schema validation, semantic
 * validation, and refinement checking - the Java shape of the Python
 * binding's (bool, list-of-strings) tuples.
 */
public final class Validation {

    /** True iff the check passed. */
    public final boolean ok;

    /** The reasons; empty when ok (except refinementValid's note). */
    public final List<String> reasons;

    public Validation(boolean ok, List<String> reasons) {
        this.ok = ok;
        this.reasons = List.copyOf(reasons);
    }

    /** A passing result with no reasons. */
    public static Validation valid() {
        return new Validation(true, List.of());
    }

    /** A failing result with a single reason. */
    public static Validation invalid(String reason) {
        return new Validation(false, List.of(reason));
    }

    /** All reasons joined with "; " (the store's rejection message form). */
    public String reason() {
        return String.join("; ", reasons);
    }

    /** True iff any reason contains the given fragment. */
    public boolean anyReasonContains(String fragment) {
        for (String r : reasons) {
            if (r.contains(fragment)) {
                return true;
            }
        }
        return false;
    }
}
