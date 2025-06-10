# art

Implementation of the Asynchronous Ratcheting Tree (ART) data structure and
associated protocols, based on the CCS '18 paper
[On Ends-to-Ends Encryption: Asynchronous Group Messaging with Strong Security
Guarantees](https://dl.acm.org/doi/10.1145/3243734.3243747) by Cohn-Gordon, et al.


# Building

The module is intended as a library that other projects may use.  However,
the module includes a set of command-line utilities that exercise the major
operations.  These utilities are:

- `genpkey`:
    Generate ephemeral keys (aka setup keys) and identity keys.
- `pkeyutl`
    Create and verify signatures on files.
- `setup_group`
    Setup the ART group.
- `process_setup_message`
    Process a group setup message as a group member at a given index.
- `update_key`
    Update the leaf key for a member at given position.
- `process_update_message`
    Process a key update message as a group member at given index.

Each command-line utility provides detailed usage statement when invoked with
the `-h` or `--help` option.

To build the command-line utilities, enter:

```
make
```

There is a also a `clean` target to delete these built utilities:

```
make clean
```

# Running

1. Start with generating identity and ephemeral keys for the participants

   ```bash
   # Generating individually
   ./genpkey -keytype ek alice
   ./genpkey -keytype ik alice

   # Generating in bulk
   for name in alice bob cici dave; do for type in ik ek; do ./genpkey -keytype $type $name; done; done
   ```

   Move the certificates to data folder after generation.

   ```bash
   mv *.pem cmd/setup_group/data/
   ```

2. Initiating Group Setup (initiator here = alice)
   ```
   ./setup_group -initiator alice ./cmd/setup_group/data/4.conf ./cmd/setup_group/data/alice-ik.pem
   ```
3. For processing the setup message by another participant (participant here = bob, index = 2)
   ```
   ./process_setup_message -out-state bob-state.json 2 ./cmd/setup_group/data/bob-ek.pem ./cmd/setup_group/data/alice-ik-pub.pem 4.conf.dir/setup.msg
   ```
4. Update Key: Cici updates her key (assuming Cici already has been setup as a member)

   ```
   ./update_key -update-file cici_update_key 3 cici-state.json
   ```

5. Process Update Message: Bob applies the key update message sent by Cici in Step 4

   ```
   ./process_update_message 2 ./cmd/setup_group/data/bob-ek.pem bob-state.json cici_update_key
   ```

# Benchmarking

The `benchmarking` branch contains Go benchmarks for the ART implementation.
(The branch includes a few small changes and instrumentation to the code to facilitate
 benchmarking.) To run the benchmarks, switch to this branch and enter:

```
make benchmark
```

