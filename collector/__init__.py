"""OSINT collector: automated, de-duplicated, evidence-backed collection.

Seeds (username, email, phone, domain, ...) go through modules; every finding is
normalised to a canonical key, merged into one entity per key, scored by how many
independent modules confirm it, and pivoted further only when it is worth it.
Results export to OSINT Graph (.osint.json) for the analyst.
"""

__version__ = "0.1.0"
