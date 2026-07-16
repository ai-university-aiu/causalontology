% mentova_gardener.pl - the first synthetic mind gardening the commons.
% A PrologAI/Mentova-style glass-box agent that: reads the stigmergy
% frontier (GET /gaps), chooses the most valuable missing_field gap,
% learns the missing fields BY ACTING (interventions in its microworld,
% not passive observation), contributes a refinement object and a signed
% intervention-grade assertion, and watches the gap close.
% The microworld here stands in for Mentova's live environment; the loop
% (read frontier -> act -> induce -> sign -> contribute) is the real thing.
% Run: CAUSALONTOLOGY_STORE=http://127.0.0.1:8785 swipl mentova_gardener.pl

% Load the HTTP client library for reading and writing store endpoints.
:- use_module(library(http/http_open)).
% Load the JSON library for reading and writing store payloads as dicts.
:- use_module(library(http/json)).
% Load the process library to reach the reference SDK's Ed25519 signer.
:- use_module(library(process)).

% Announce a glass-box narration line so every step shows its reasoning.
narrate(Format, Args) :-
    % Print the line with a gardener prefix to standard output.
    format("gardener: ~@~n", [format(Format, Args)]).

% Resolve the store base URL from the environment, with the default port.
store_base(Base) :-
    % Take CAUSALONTOLOGY_STORE when set, otherwise the RFC 8785 port.
    ( getenv('CAUSALONTOLOGY_STORE', Base) -> true
    ; Base = 'http://127.0.0.1:8785' ).

% Fetch a JSON document from a store path into a dict.
get_json(Path, Dict) :-
    % Build the full URL from the base and the path.
    store_base(Base), atom_concat(Base, Path, URL),
    % Open the URL, read the JSON body as a dict, and close the stream.
    setup_call_cleanup(http_open(URL, In, []),
                       json_read_dict(In, Dict),
                       close(In)).

% Post a dict as JSON to a store path and read the JSON reply.
post_json(Path, Dict, Reply) :-
    % Build the full URL from the base and the path.
    store_base(Base), atom_concat(Base, Path, URL),
    % Serialize the dict to an atom of JSON text.
    with_output_to(atom(Body), json_write_dict(current_output, Dict, [])),
    % Post the body, accepting any status so replies are inspectable.
    setup_call_cleanup(
        http_open(URL, In, [method(post),
                            post(atom('application/json', Body)),
                            status_code(_Code)]),
        json_read_dict(In, Reply),
        close(In)).

% Sign a record through the reference SDK's Ed25519 helper (glass-box
% composition: Mentova reasons in Prolog; the byte plumbing is the SDK's).
sign_record(Record, Seed, Signed) :-
    % Locate the helper script that sits beside this program.
    source_file(sign_record(_, _, _), Here),
    % Derive the helper path from this file's directory.
    file_directory_name(Here, Dir),
    % Compose the full helper path.
    atomic_list_concat([Dir, '/sign_helper.py'], Helper),
    % Start the helper with the seed name, piping JSON in and out.
    process_create(path(python3), [Helper, Seed],
                   [stdin(pipe(ToChild)), stdout(pipe(FromChild))]),
    % Send the unsigned record to the helper.
    json_write_dict(ToChild, Record, []),
    % Close the input so the helper sees end of file.
    close(ToChild),
    % Read the signed record back.
    json_read_dict(FromChild, Signed),
    % Close the output stream.
    close(FromChild).

% One microworld trial: press the button and observe, deterministically.
% Every fiftieth press hits the worn contact and fails; the lamp delay
% cycles under one second. Acting, not watching: the gardener's own hand
% is on the switch, so coincidence cannot masquerade as cause.
trial(T, Outcome, Delay) :-
    % The worn contact: multiples of fifty fail to light the lamp.
    ( 0 is T mod 50 -> Outcome = failure ; Outcome = success ),
    % The observed delay in tenths of a second, always under one second.
    Delay is (T * 7 mod 10) / 10.

% Run N intervention trials and tally successes and the largest delay.
run_trials(N, Successes, MaxDelay) :-
    % Collect the outcome and delay of every trial from one to N.
    findall(O-D, (between(1, N, T), trial(T, O, D)), Pairs),
    % Count the successful presses.
    include([success-_]>>true, Pairs, Wins),
    % The tally of successes.
    length(Wins, Successes),
    % The largest delay seen across all trials.
    aggregate_all(max(D), member(_-D, Pairs), MaxDelay).

% The gardening loop: one full pass over the frontier.
main :-
    % Step 1: read the frontier - the most valuable missing_field gaps.
    get_json('/gaps?kind=missing_field', Gaps),
    % Take the ranked list of open gaps.
    get_dict(items, Gaps, Items),
    % Refuse politely when the wall has no open gaps to fill.
    ( Items = [] -> narrate("the frontier is clean; nothing to garden", []),
                    halt(0) ; true ),
    % Choose the top-ranked gap - the store already ordered by value.
    Items = [Gap|_],
    % Name the chosen claim.
    get_dict(id, Gap, ClaimId),
    % Show the choice and the reason.
    get_dict(value, Gap, Value),
    % Narrate the glass-box selection.
    narrate("frontier read; chose gap ~w (value ~w) - the wall's most wanted brick", [ClaimId, Value]),
    % Step 2: fetch the partial claim and its vocabulary.
    atom_concat('/objects/', ClaimId, ClaimPath),
    % Read the claim with its materialized view.
    get_json(ClaimPath, ClaimView),
    % Take the content object itself.
    get_dict(object, ClaimView, Claim),
    % Its cause and effect occurrent identifiers.
    get_dict(causes, Claim, Causes), get_dict(effects, Claim, Effects),
    % Read the labels so the narration speaks in words, not hashes.
    Causes = [CauseId|_], Effects = [EffectId|_],
    % Fetch the cause occurrent.
    atom_concat('/objects/', CauseId, CausePath),
    % Read it.
    get_json(CausePath, CauseView),
    % Its label.
    get_dict(label, CauseView.object, CauseLabel),
    % Fetch the effect occurrent.
    atom_concat('/objects/', EffectId, EffectPath),
    % Read it.
    get_json(EffectPath, EffectView),
    % Its label.
    get_dict(label, EffectView.object, EffectLabel),
    % Narrate what the claim says and what it lacks.
    narrate("the claim: ~w causes ~w - but with no window and no modality; a promise without a shape", [CauseLabel, EffectLabel]),
    % Step 3: ACT. One hundred interventions in the microworld.
    narrate("intervening: one hundred presses, my own hand on the switch", []),
    % Run the trials.
    run_trials(100, Successes, MaxDelay),
    % The induced reliability.
    Rate is Successes / 100,
    % Narrate the tally.
    narrate("tally: ~w/100 lit the lamp; slowest response ~w seconds", [Successes, MaxDelay]),
    % Step 4: induce the missing fields from the interventions.
    ( Rate >= 0.9 -> Modality = sufficient ; Modality = contributory ),
    % The temporal window: never slower than one second.
    Temporal = _{minimum_delay: 0, maximum_delay: 1, unit: seconds},
    % Narrate the induction, glass-box.
    narrate("induced: modality ~w (rate ~w), window 0..1 seconds - because acting beats watching", [Modality, Rate]),
    % Step 5: contribute the refinement object.
    Refinement = _{type: cro, causes: Causes, effects: Effects,
                   temporal: Temporal, modality: Modality,
                   refines: ClaimId},
    % Write it to the commons.
    post_json('/objects', Refinement, RefReply),
    % The refinement's content-addressed identifier.
    get_dict(id, RefReply, RefId),
    % Narrate the contribution.
    narrate("refinement minted: ~w (refines ~w)", [RefId, ClaimId]),
    % Step 6: sign the intervention-grade assertion and contribute it.
    sign_record(_{type: assertion, about: RefId,
                  evidence_type: intervention,
                  strength: Rate, confidence: 0.95,
                  timestamp: "2026-07-13T06:00:00Z"},
                mentova, SignedAssertion),
    % Write the signed record to the commons.
    post_json('/records', SignedAssertion, AstReply),
    % The record identifier confirms acceptance.
    get_dict(id, AstReply, AstId),
    % Narrate the signature.
    narrate("assertion signed and landed: ~w (evidence: intervention - the strongest grade)", [AstId]),
    % Step 7: read the frontier again and confirm the brick is laid.
    get_json('/gaps?kind=missing_field', GapsAfter),
    % The remaining open gaps.
    get_dict(items, GapsAfter, ItemsAfter),
    % The chosen gap must be gone.
    ( member(G, ItemsAfter), get_dict(id, G, ClaimId)
    -> narrate("unexpected: the gap survives", []), halt(1)
    ;  narrate("the gap I chose is gone from the frontier - the wall shows the next worker a different brick", []),
       halt(0) ).

% Run the gardening loop when this program is loaded.
:- initialization(main).
