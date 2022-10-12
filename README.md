# QWIC: QUIC Watchful Information Collector

This project is a proof of concept for an end-host monitoring application specialized in collecting information about QUIC connections. The project is at the core of Matteo Franzil's Master Thesis.

More information - such as installation instructions - will be inserted here as the project grows to completion.

## Usage

You need the edited version of Quiche from the [repository](https://github.com/mfranzil/quiche) to test out this application.

Client-side (you must insert your server endpoint; `--silent` flag is optional and silences the application).

```bash
./client-request.sh https://192.168.50.1:4433/index-2m.html --silent
```

Server-side:

```bash
./server-request.sh --silent
```

On another shell, if conda is installed (sudo is needed):

```bash
conda activate qwic
sudo env "PATH=$PATH" python3 src/main.py -i br-fc2518b3193b -m SC -f monitor -d auto -x L30 -c 1M >/dev/null
```

If conda is not installed, you can straight up run the main.py script:

```bash
sudo python3 src/main.py ...
```

The flags are the following:

- `-i`: the interface to listen on (e.g. `br-eth0`)
- `-m`: the mode of collection: may be XDP, TC (if eBPF is enabled), SC (Scapy), or PY (Pyshark)
- `-f`: the monitoring file to which the application sends alerts
- `-d`: the data file to which the application writes data; if "auto", the application derives the filename from the configuration
- `-x`: the feature flags enabled in the application; for now see the `src/flags.py` file for the list of flags
- `-c`: optional comment to be added in the data file, if it has been set to "auto"

## Contributors

- Thesis writer: [Matteo Franzil](https://gitlab.fbk.eu/mfranzil) ([other profile](https://matteo.franzil.com/)) `<mfranzil@fbk.eu>`
- Supervisor: [Domenico Siracusa](https://gitlab.fbk.eu/dsiracusa) `dsiracusa@fbk.eu`
- Supervisor: [Gianni Antichi](https://gianniantichi.github.io/) `g.antichi@qmul.ac.uk`
- Collaborator: [Simone Magnani](https://gitlab.fbk.eu/smagnani) `smagnani@fbk.eu`
