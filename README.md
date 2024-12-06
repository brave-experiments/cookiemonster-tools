# Tools for interacting with Cookiemonster API

## Run a crawl

### Init

Initialize the Python virtual environment and install the requirements. For example:

```bash
python3 -m venv env
source env/bin/activate
pip3 install -r requirements.txt
```

You will also need a list of domains to crawl. It presumes a list of Tranco domains, though other lists might work.

You can obtain the latest Tranco list with subdomains here: https://tranco-list.eu/top-1m-incl-subdomains.csv.zip

Alternatively, run the `get_latest_tranco.sh` script (curls and unzips that file).

### Using 
You need to pass as input a CSV file of domains. You also need to pass an output file. If the supplied output file already exists, it will be appended to, not overwritten. Also, you can pass in a `--skip` parameter to skip the first N rows. All this helps restart crawls. 

The script will both print to stdout and write to the output file.

```bash
python3 crawl.py -i top-1m.csv -o sept14-crawl-results.txt
```
