# StructuredArtifactDumper
This is a script to run from a removable drive, which will iterate through multiple security tools and perform forensic aquisition using each, then create an overview of the results and stored hashes. initial arguments taken are minimal (such as hostname, investigator name, case description) and are passed to each forensic tool as required.

# History

A former college instructor of mine from a graudate forensics course provided the class with a cmd.exe bat script for pulling consistent forensic artifacts and appending result files with dates, etc. This was all good and well, but cmd.exe has long since been surpassed, and I thought to modernize the concept using PowerShell and a more object-oriented approach.
I ramped it up to 400+ lines of PowerShell to call RM dump, disk image, and even some initial volatility analysis, but the script is still in its infancy.

# Purpose

The inital run of the project had field-based forensic investigators and collectors in mind. Given an NVMe drive of sufficient size (and the initial test-drive was a 1TB stick), multiple collections can be made from many sources on-site during an investigtion, all stored in individually named directories within a 'results' partition on the drive.

# Future plans

My intention for the project is to ultimately seprate the analysis functions from the collection functions, where the collection would occur on-site, and the results drive could be then be plugged in to the investgator's system, which would ingest the results and begn analysis (automatically). This is planned to include database storage of results/artifacts/hashes/collector names, prevention of redundancies/duplicate ingestion, and leveraging the newer 'profile free' versions to volatility which can auto-detect the operating system without needing a manual argument passed.

Additionally, testing has begun on using PowerShell to determine the BIOS settings, disable secure boot, put USB as the primary boot source, and force a reboot. The reboot would cause a Linux Forensics distribution (on a dfferent partition of the same NVMe drive) to boot, and an auto-run to execute which would image all physical disks, before reversing the BIOS settings, and calling another reboot. This way, a single phsycial NVMe USB drive could collect ALL data with very minimal user interaction, but maximum consistency and fidelity of results. This typically diminishes with the practice of rebooting into another OS, modifying BIOS settings etc (which until now, have been a manual process).

Smarter not harder, kids.
