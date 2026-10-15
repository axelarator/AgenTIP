# FlowCarp custom models

FlowCarp's community edition (CC BY-ND) ships 17 common protocols and 8
malicious ones (Mirai, Gh0st RAT, njRAT, XWorm, …). It can also **build
your own models** — confirmed available in the free edition — so a family
it does not know can still be labelled once you have captured enough of it.

## When to bother

Build a model for a C2 family we track that FlowCarp does not already name,
when we have real sessions of it in Arkime (detonations in the lab, or
captured probe traffic to a live listener). A model only pays off once the
family turns up on more than one host; for a one-off, read the flow by hand.

## Workflow

1. **Collect ≥10 sessions** of one family's traffic (100+ from different
   hosts gives real precision). Put them in a directory here, one directory
   per family, captures of *that family only* — any other traffic teaches
   the model the wrong shape:

   ```
   data/flowcarp/training/gh0st-variantX/*.pcap
   ```

   Pull them from Arkime by session expression, the same source the live
   labeller uses, e.g. `ip.dst == <listener> && port.dst == <p>`.

2. **Build the model** into `data/flowcarp/models/` (where every
   `graph netwatch --flowcarp` run loads it, via `flowcarp.model_args()`).
   Tag it `MALICIOUS` so a match raises an alert that lands in `c2_hits`:

   ```
   flowcarp --input directory:Once:data/flowcarp/training/gh0st-variantX/ \
            --output model:"Gh0st variantX":MALICIOUS:data/flowcarp/models/gh0st-variantX.fcp
   ```

   `cti.netwatch.flowcarp.build_model_command(name, tags, src, out)` returns
   exactly this argv if you want to drive it from Python.

3. **It is loaded automatically.** No code change — any `.fcp` under
   `data/flowcarp/models/` is passed with `--model` on the next label run,
   alongside the built-in families.

## Notes

- Training pcap and the `.fcp` models are local artifacts; `data/` is
  gitignored, so nothing here is published. Keep captures of real malicious
  infrastructure out of any commit regardless.
- The binary is not installed by this repo. Install `flowcarp` on the agent
  VM (or set `CTI_FLOWCARP_BIN`); building a model needs it just as labelling
  does.
