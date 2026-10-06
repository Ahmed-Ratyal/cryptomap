# Reproduce and explain the demonstration

1. Install the requirement and run `python demo_run.py` from the repository folder.
2. Open `results/demo/before/report.html` and `results/demo/after/report.html`.
3. Verify that the portal's 14-day warning disappears after replacement. Its unknown exchange-group review remains; the expired archive is unchanged.
4. Compare public certificate fingerprints with `tls_observations.json`. Each handshake must present the certificate the inventory inspected.
5. Run `python -m unittest discover -s tests -v` to check the complete workflow and validation boundaries.

To explore the rules, copy `data/sample_inventory.csv` into `results`, change SIM-01's fictional protection lifetime from 15 to 2 and run the inventory tool on your copy. The long-term confidentiality rule should stop triggering for that record while sensitive-data review can remain. Changing an assumption is not a real system discovery.

The public examples use a fixed historical assessment date. Running the live demo generates new certificates using today's date. Private keys are disposable; never put private-key files in the repository.
