import uuid
from io import BytesIO
from zipfile import ZipFile

import requests
import untangle

from core.models import Cwe
from core.management.commands import BaseCommand


MITRE_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


class Command(BaseCommand):
    help = "Import CWE"

    def handle(self, *args, **kwargs):
        self.info("Importing CWE list...")

        # Download the file
        with self.timed_operation("Downloading {}...".format(MITRE_CWE_URL)):
            resp = requests.get(MITRE_CWE_URL).content

        # Parse weaknesses
        with self.timed_operation("Parsing cwes..."):
            z = ZipFile(BytesIO(resp))
            raw = z.open(z.namelist()[0]).read()
            obj = untangle.parse(raw.decode("utf-8"))
            weaknesses = obj.Weakness_Catalog.Weaknesses.Weakness
            categories = obj.Weakness_Catalog.Categories.Category

        # Create the objects
        cwes = []
        with self.timed_operation("Creating mappings..."):
            for c in weaknesses + categories:
                data = dict(
                    id=str(uuid.uuid4()),
                    cwe_id=f"CWE-{c['ID']}",
                    name=c["Name"],
                    description=c.Description.cdata
                    if hasattr(c, "Description")
                    else c.Summary.cdata,
                )
                cwes.append(Cwe(**data))

        with self.timed_operation("Inserting CWE..."):
            Cwe.objects.bulk_create(cwes)

        self.info("{} CWE imported.".format(len(cwes)))
        del cwes
