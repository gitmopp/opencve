import gzip
import json
from turtle import update
import uuid
from io import BytesIO
from venv import create

import arrow
import requests

from changes.models import Change, Event, Task
from core.management.commands import BaseCommand
from core.models import Cve
from core.utils import convert_cpes, flatten_vendors, get_cwes

"""from opencve.commands import header, info, timed_operation
from opencve.commands.imports.cpe import get_slug
from opencve.extensions import db
from opencve.utils import convert_cpes, flatten_vendors, get_cwes
from opencve.models import get_uuid
from opencve.models.changes import Change
from opencve.models.cve import Cve"""


NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


class Command(BaseCommand):
    help = "Import the CVE list"

    @staticmethod
    def get_slug(vendor, product=None):
        slug = vendor
        if product:
            slug += "-{}".format(product)
        return slug

    def handle(self, *args, **kwargs):
        mappings = {"vendors": {}, "products": {}}

        # Create the initial task
        task = Task()
        task.save()
        task_id = task.id

        for year in range(BaseCommand.CVE_FIRST_YEAR, BaseCommand.CURRENT_YEAR + 1):
            self.header("Importing CVE for {}".format(year))
            mappings.update({"cves": [], "changes": [], "events": []})

            # Download the file
            url = NVD_CVE_URL.format(year=year)
            with self.timed_operation("Downloading {}...".format(url)):
                resp = requests.get(url).content

            # Parse the XML elements
            with self.timed_operation("Parsing JSON elements..."):
                raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
                del resp
                items = json.loads(raw.decode("utf-8"))["CVE_Items"]
                del raw

            with self.timed_operation("Creating model objects..."):

                for item in items:
                    cve_db_id = str(uuid.uuid4())
                    change_db_id = str(uuid.uuid4())

                    summary = item["cve"]["description"]["description_data"][0]["value"]
                    cvss2 = (
                        item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                        if "baseMetricV2" in item["impact"]
                        else None
                    )
                    cvss3 = (
                        item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                        if "baseMetricV3" in item["impact"]
                        else None
                    )

                    # Construct CWE and CPE lists
                    cwes = get_cwes(
                        item["cve"]["problemtype"]["problemtype_data"][0]["description"]
                    )
                    cpes = convert_cpes(item["configurations"])
                    vendors = flatten_vendors(cpes)

                    # Create the CVE and Change mappings
                    created_at = arrow.get(item["publishedDate"]).datetime
                    updated_at = arrow.get(item["lastModifiedDate"]).datetime

                    mappings["cves"].append(
                        Cve(
                            **dict(
                                id=cve_db_id,
                                cve_id=item["cve"]["CVE_data_meta"]["ID"],
                                summary=summary,
                                json=item,
                                vendors=vendors,
                                cwes=cwes,
                                cvss2=cvss2,
                                cvss3=cvss3,
                                created_at=created_at,
                                updated_at=updated_at,
                            )
                        )
                    )
                    mappings["changes"].append(
                        Change(
                            **dict(
                                id=change_db_id,
                                created_at=created_at,
                                updated_at=updated_at,
                                json=item,
                                cve_id=cve_db_id,
                                task_id=task_id,
                            )
                        )
                    )
                    mappings["events"].append(
                        Event(
                            **dict(
                                id=str(uuid.uuid4()),
                                created_at=created_at,
                                updated_at=updated_at,
                                type=Event.EventType.NEW_CVE,
                                details={},
                                is_reviewed=True,
                                cve_id=cve_db_id,
                                change_id=change_db_id,
                            )
                        )
                    )

                    # Create the vendors and their products
                    for vendor, products in cpes.items():

                        # Create the vendor
                        if vendor not in mappings["vendors"].keys():
                            mappings["vendors"][vendor] = dict(
                                id=str(uuid.uuid4()), name=vendor
                            )

                        for product in products:
                            if (
                                self.get_slug(vendor, product)
                                not in mappings["products"].keys()
                            ):
                                mappings["products"][
                                    self.get_slug(vendor, product)
                                ] = dict(
                                    id=str(uuid.uuid4()),
                                    name=product,
                                    vendor_id=mappings["vendors"][vendor]["id"],
                                )

            # Insert the objects in database
            with self.timed_operation("Inserting CVE..."):
                Cve.objects.bulk_create(mappings["cves"])
                Change.objects.bulk_create(mappings["changes"])
                Event.objects.bulk_create(mappings["events"])

            self.info("{} CVE imported.".format(len(mappings["cves"])))

            # Free the memory after each processed year
            del mappings["cves"]
            del mappings["changes"]
            del mappings["events"]
