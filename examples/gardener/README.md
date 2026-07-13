# The Mentova gardener — the first synthetic mind gardening the commons

`mentova_gardener.pl` is a glass-box SWI-Prolog agent in the PrologAI/Mentova
style that closes the loop the whole project was built for:

1. **Reads the frontier** — `GET /gaps?kind=missing_field`, taking the store's
   own value ranking ("the wall's most wanted brick").
2. **Acts** — one hundred interventions in its microworld, its own hand on
   the switch. Acting, not watching: coincidence cannot survive your own
   hand on the switch.
3. **Induces** — the missing temporal window and modality from the tally
   (98/100 within a second → `sufficient`, `0..1 seconds`).
4. **Contributes** — mints the `refines` object, then signs an
   **intervention-grade** assertion with its own Ed25519 key (the signing
   bytes come from the reference SDK via `sign_helper.py` — Mentova reasons
   in Prolog; the plumbing is the standard's).
5. **Verifies the wall moved** — reads `/gaps` again and confirms the gap it
   chose is gone from everyone's frontier.

Every line of the Prolog carries its English explanation (the
English-Readable Code discipline), and every step narrates its reason.

The microworld stands in for Mentova's live environments; the loop — read
frontier → act → induce → sign → contribute — is the real thing, and it runs
against the real store over real HTTP.

## Run it

```
python3 store/server/server.py &          # a live commons
swipl examples/gardener/mentova_gardener.pl
```

## Test it

```
python3 examples/gardener/test_gardener.py
...
11/11 gardener checks passed
```

The test seeds a degenerate claim, builds demand on it, runs the gardener as
a real subprocess, and verifies: the refinement is valid by rule 3, the
assertion is intervention-grade with a verifying signature under the
gardener's own key, the gap left the frontier, and the gardener now has a
glass-box reputation computed from its signed history.
