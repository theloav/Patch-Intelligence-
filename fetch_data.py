# fetch_data.py
import requests
import json
import time
import os
import logging
from dotenv import load_dotenv

log = logging.getLogger(__name__)

def get_npm_package_info(package_name):
    """Fetches information for a given npm package from the npm registry."""
    log.debug(f"Entering get_npm_package_info with: {package_name}")
    url = f"https://registry.npmjs.org/{package_name}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        response.encoding = 'utf-8'  # FORCE UTF-8 ENCODING
        data = response.json()
        log.debug(f"get_npm_package_info: Received data: {data.keys()}")
        return data
    except requests.exceptions.RequestException as e:
        log.error(f"Error fetching data for {package_name}: {e}")
        return None
    finally:
        log.debug("Exiting get_npm_package_info")

def get_cve_data(cpe_name):
    """Fetches CVE data from NVD based on a CPE name, with retries."""
    log.debug(f"Entering get_cve_data with: {cpe_name}")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "cpeName": cpe_name,
        "resultsPerPage": 20,
        "startIndex": 0
    }
    all_cves = []

    load_dotenv()
    api_key = os.environ.get("NVD_API_KEY")

    if not api_key:
        log.error("Error: NVD_API_KEY not found in .env file or environment.")
        return None

    headers = {"apiKey": api_key}

    retries = 3
    delay = 1.2

    while True:
        try:
            response = requests.get(base_url, params=params, headers=headers)
            response.raise_for_status()
            response.encoding = 'utf-8'
            try:
                data = response.json()
                log.debug(f"Successfully decoded JSON from NVD. Keys: {data.keys()}")
            except json.JSONDecodeError as e:
                log.error(f"JSONDecodeError: Could not decode JSON from NVD: {e}")
                log.error(f"Response content: {response.text}")
                return None

            if "vulnerabilities" in data:
                all_cves.extend(data["vulnerabilities"])
            else:
                log.warning(f"NVD response missing 'vulnerabilities' key for CPE: {cpe_name}")

            total_results = data.get("totalResults", 0)
            log.debug(f"Total results: {total_results}, startIndex: {params['startIndex']}, resultsPerPage: {params['resultsPerPage']}")
            if total_results <= params["startIndex"] + params["resultsPerPage"]:
                break

            params["startIndex"] += params["resultsPerPage"]
            log.debug(f"Fetched page, sleeping for {delay} seconds...")
            time.sleep(delay)

        except requests.exceptions.RequestException as e:
            log.error(f"Error fetching CVE data for {cpe_name}: {e}")
            if retries > 0 and (response.status_code == 403 or response.status_code == 429):
                log.warning(f"Retrying in {delay} seconds...")
                time.sleep(delay)
                retries -= 1
                delay *= 2  # Exponential backoff
            else:
                log.error("Max retries reached or other error. Giving up.")
                return None
        except Exception as e: #Catch any unexpected exception.
            log.exception(f"An unexpected error has occured in get_cve_data: {e}")
            return None

        log.debug("Exiting get_cve_data")
        return all_cves

def generate_cpe(package_name, version, vendor="npmjs"):
    """Generates a best-guess CPE string for an npm package."""
    return f"cpe:2.3:a:{vendor}:{package_name}:{version}:*:*:*:*:node.js:*:*"

def collect_package_data(package_name, max_versions=None):
    """Collects data for an npm package and its vulnerabilities."""
    log.debug(f"Entering collect_package_data with: {package_name}")
    package_data = get_npm_package_info(package_name)
    if not package_data:
        log.debug(f"collect_package_data: package_data is None")
        return None
    log.debug(f"collect_package_data: package_data keys: {package_data.keys()}")

    collected_info = {
        "name": package_name,
        "versions": {},
    }

    versions_processed = 0
    try:
        for version, details in package_data.get("versions", {}).items():
            if max_versions is not None and versions_processed >= max_versions:
                log.warning(f"Reached max_versions ({max_versions}). Stopping.")
                break
            try:  # Inner try...except
                cpe = generate_cpe(package_name, version)
                cve_data = get_cve_data(cpe)

                version_info = {
                    "version": version,
                    "cpe": cpe,
                    "vulnerabilities": [],
                    "tarball": details.get("dist", {}).get("tarball"),
                }

                if cve_data:
                    for cve_entry in cve_data:
                        cve_id = cve_entry["cve"]["id"]
                        description = "No description available."
                        for desc in cve_entry["cve"]["descriptions"]:
                            if desc["lang"] == "en":
                                description = desc["value"]
                                break

                        version_info["vulnerabilities"].append({
                            "cve_id": cve_id,
                            "description": description,
                        })

                collected_info["versions"][version] = version_info
                versions_processed += 1
            except Exception as e:
                log.exception(f"Error processing version {version} of {package_name}: {e}")
                continue  # Continue to the next version

    except Exception as e:
        log.exception(f"An unexpected error occurred while processing {package_name}: {e}")
        return None

    log.debug(f"Exiting collect_package_data. Processed {versions_processed} versions.")
    return collected_info