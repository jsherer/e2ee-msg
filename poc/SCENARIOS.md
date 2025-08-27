## Scenario 1: Single Initiation (Clean)
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->accepts init     [Derives SharedSecret_1 from DH(v_i_priv, E_a)]
B->ratchets->A      [E_b1, Enc_DR(data_2)]
A->decrypts via DR  [Uses SharedSecret_1 to decrypt]
A->ratchets->B      [E_a1, Enc_DR(data_3)]
B->decrypts via DR  [Continues ratchet]
```

## Scenario 2: Simultaneous - Both Accept (Double Ladder)
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b]  
A->accepts B's init [Has both secrets: DH(e_a,V_i_b) and DH(v_j_priv,E_b)]
B->accepts A's init [Has both secrets: DH(e_b,V_j_a) and DH(v_i_priv,E_a)]
A->merges ladders   [RootKey = KDF(secret_1 || secret_2)]
B->merges ladders   [RootKey = KDF(secret_1 || secret_2)]
A->ratchets->B      [E_a1, Enc_DR(data_3)]
B->decrypts via DR  [Using merged RootKey]
B->ratchets->A      [E_b1, Enc_DR(data_4)]
A->decrypts via DR  [Using merged RootKey]
```

## Scenario 3: Simultaneous - Delayed Recognition
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b] (crosses in transit)
B->accepts A's init [Creates single ladder session_1]
B->ratchets->A      [E_b1, Enc_DR(data_3), includes hint: "using your init"]
A->accepts B's init [Recognizes double ladder situation]
A->merges->B        [E_a1, Enc_DR(data_4), includes: "merge to double ladder"]
B->upgrades session [Switches from single to double ladder]
B->ratchets->A      [E_b2, Enc_DR(data_5)]
```

## Scenario 4: Triple Device (A has two devices A1, A2)
```
A1->initiates->B    [E_a1, V_i, Enc(data_1), Sig_a1]
A2->initiates->B    [E_a2, V_k, Enc(data_2), Sig_a2]
B->initiates->A1    [E_b, V_j, Enc(data_3), Sig_b]
B->initiates->A2    [E_b, V_j, Enc(data_3), Sig_b]

A1->accepts B init  [Double ladder: DH(e_a1,V_j) + DH(v_i_priv,E_b)]
A2->accepts B init  [Double ladder: DH(e_a2,V_j) + DH(v_k_priv,E_b)]
B->accepts A1 init  [Double ladder with A1]
B->accepts A2 init  [Double ladder with A2]

Result: Two separate double-ladder sessions (B<->A1, B<->A2)
```

## Scenario 5: Lost Initial Message
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a] (LOST in transit)
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b]
A->accepts B's init [Single ladder only]
A->ratchets->B      [E_a1, Enc_DR(data_3)]
B->decrypts via DR  [Single ladder session established]

Later:
A->retransmits->B   [E_a, V_i, Enc(data_1), Sig_a] (retry)
B->detects old msg  [Timestamp/nonce shows this is stale]
B->ignores          [Continues with established session]
```

## Scenario 6: Upgrade from Single to Double
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->accepts A's init [Single ladder established]
B->ratchets->A      [E_b1, Enc_DR(data_2)]
A->decrypts via DR  [Using single ladder]

(B realizes they want to strengthen security)
B->initiates->A     [E_b, V_j, Enc(data_3), Sig_b, flag: "UPGRADE"]
A->accepts upgrade  [Now has both directions]
A->confirms->B      [E_a2, Enc_DR(data_4), flag: "UPGRADED"]

Both now using double ladder going forward
```

## Scenario 7: Race with Acknowledgment
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b]
B->accepts A's init [Realizes simultaneous]
B->ack merge->A     [E_b1, Enc_DR("using double"), metadata: DOUBLE_LADDER]
A->accepts B's init [Confirms double ladder]
A->ack merge->B     [E_a1, Enc_DR("confirmed"), metadata: DOUBLE_LADDER]

Both continue with double ladder
```

## Scenario 8: Asymmetric Recognition
```
A->initiates->B     [E_a, V_i, Enc(data_1), Sig_a]
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b] (delayed)
A->timeout          [Proceeds with single ladder after 5 seconds]
A->ratchets->B      [E_a1, Enc_DR(data_3)]
B->accepts A's init [Sees ratchet message, realizes A went single]
B->adapts           [Drops own init, uses single ladder]
B->ratchets->A      [E_b1, Enc_DR(data_4)]
```

## Scenario 9: Multiple Simultaneous Attempts
```
A->initiates->B     [E_a1, V_i, Enc(data_1), Sig_a] 
A->initiates->B     [E_a2, V_k, Enc(data_1), Sig_a] (retry, new ephemeral)
B->initiates->A     [E_b, V_j, Enc(data_2), Sig_b]
B->accepts A's 1st  [Creates double ladder with E_a1]
B->rejects A's 2nd  [Deduplicates based on message content]
A->accepts B's init [Creates double ladder with E_b]

Both use ladder from (E_a1,E_b) pair
```

## Implementation State Machine

```typescript
enum SessionState {
  NONE,
  INIT_SENT,           // Sent initial, waiting
  INIT_RECEIVED,       // Received initial, no response yet
  SINGLE_ESTABLISHED,  // One ladder active
  DOUBLE_ESTABLISHED,  // Two ladders merged
  RATCHETING          // Normal Double Ratchet operation
}

interface StateTransitions {
  // NONE -> INIT_SENT: When we initiate
  // NONE -> INIT_RECEIVED: When we receive init
  // INIT_SENT -> DOUBLE_ESTABLISHED: Receive init while waiting
  // INIT_SENT -> SINGLE_ESTABLISHED: Timeout or receive ratchet
  // INIT_RECEIVED -> SINGLE_ESTABLISHED: We accept their init
  // SINGLE_ESTABLISHED -> DOUBLE_ESTABLISHED: Upgrade
  // *_ESTABLISHED -> RATCHETING: After first ratchet
}
```

These scenarios cover all the edge cases and show how the protocol gracefully handles various timing conditions while maintaining 0-RTT properties!
