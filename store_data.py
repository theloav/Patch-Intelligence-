# store_data.py
from arango import ArangoClient, ArangoError
import json
import logging
from fetch_data import collect_package_data

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename="patch_intel.log",
    filemode="w",
)
log = logging.getLogger(__name__)

def store_data_in_arangodb(package_data):
    """Stores the collected package and CVE data in ArangoDB."""
    try:  # Wrap the ENTIRE function in a try...except
        log.debug("Entering store_data_in_arangodb")

        if not package_data:
            log.error("store_data_in_arangodb received None for package_data!")
            return

        if not isinstance(package_data, dict) or 'name' not in package_data:
            log.error(f"Invalid package_data: {package_data}")
            return
        log.debug(f" package: {package_data['name']}")

        log.debug("Creating ArangoClient instance...")
        client = ArangoClient(hosts="http://localhost:8529")
        log.debug("ArangoClient instance created.")

        log.debug("Attempting to connect to database...")
        db = client.db("PatchIntelDB", username="root", password="App@1234")
        log.debug("Database connection established.")

        log.debug("Getting collections...")
        packages_collection = db.collection("Packages")
        cves_collection = db.collection("CVEs")
        log.debug("Got collections.")

        package_name = package_data["name"]

        if not packages_collection.has(package_name):
            packages_collection.insert({"_key": package_name, "name": package_name})
            logging.info(f"Inserted package: {package_name}")
        else:
            logging.info(f"Package already exists: {package_name}")

        for version, version_info in package_data["versions"].items():
            version_key = f"{package_name}-{version}"

            if not packages_collection.has(version_key):
                packages_collection.insert({
                    "_key": version_key,
                    "package": package_name,
                    "version": version,
                    "cpe": version_info["cpe"],
                    "tarball": version_info["tarball"],
                })
                logging.info(f"Inserted version: {version_key}")
            else:
                logging.info(f"Version already exists: {version_key}")

            for cve in version_info["vulnerabilities"]:
                cve_id = cve["cve_id"]
                try:
                    if not cves_collection.has(cve_id):
                        cves_collection.insert({"_key": cve_id, "cve_id": cve_id, "description": cve["description"]})
                        logging.info(f"Inserted CVE: {cve_id}")
                    else:
                        logging.info(f"CVE already exists: {cve_id}")
                except ArangoError as e:
                    log.error(f"Error inserting/checking CVE {cve_id}: {e}")
                    continue

                # Graph operations
                if not db.has_graph('PackageGraph'):
                    graph = db.create_graph('PackageGraph')
                    logging.info("Created graph: PackageGraph")
                else:
                    graph = db.graph('PackageGraph')

                if not graph.has_edge_definition('hasVersion'):
                    edges = graph.create_edge_definition(
                        edge_collection='hasVersion',
                        from_vertex_collections=['Packages'],
                        to_vertex_collections=['Packages']
                    )
                    logging.info("Created edge definition: hasVersion")
                else:
                    edges = graph.edge_collection('hasVersion')

                if not edges.find({'_from': f'Packages/{package_name}', '_to': f'Packages/{version_key}'}):
                    edges.insert({
                        "_from": f"Packages/{package_name}",
                        "_to": f"Packages/{version_key}",
                    })
                    logging.info(f"Created edge: Packages/{package_name} -> Packages/{version_key}")

                if not graph.has_edge_definition('vulnerableTo'):
                    edges = graph.create_edge_definition(
                        edge_collection='vulnerableTo',
                        from_vertex_collections=['Packages'],
                        to_vertex_collections=['CVEs']
                    )
                    logging.info("Created edge definition: vulnerableTo")

                else:
                    edges = graph.edge_collection('vulnerableTo')

                if not edges.find({'_from': f'Packages/{version_key}', '_to': f'CVEs/{cve_id}'}):
                    edges.insert({
                        "_from": f"Packages/{version_key}",
                        "_to": f"CVEs/{cve_id}",
                    })
                    logging.info(f"Created edge: Packages/{version_key} -> CVEs/{cve_id}")

    except ArangoError as e:
        log.error(f"ArangoDB error: {e}")

    except Exception as e:
        log.exception(f"An unexpected error occurred in store_data_in_arangodb: {e}")

if __name__ == "__main__":
    packages_to_process = ["express"]

    for package_name in packages_to_process:
        logging.info(f"Processing package: {package_name}")
        package_data = collect_package_data(package_name, max_versions=5)  # Limiting to 5 versions
        if package_data:
            store_data_in_arangodb(package_data)