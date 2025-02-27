# Patch Intelligence Information System

## Overview

This project aims to create a Patch Intelligence Information System by collecting, correlating, and organizing data about software vulnerabilities and patches. It focuses on creating a knowledge graph that links CVEs (Common Vulnerabilities and Exposures), CPEs (Common Platform Enumerations), and patch information for various application libraries. This system is designed to address key challenges in modern patch management.

## Problem Statement

Modern patch management faces several challenges:

*   **Disconnect between vulnerabilities and patches:** There's often a lack of clear, direct links between vulnerability information (CVEs) and the specific patches that fix them. This makes it difficult for IT and development teams to quickly identify and apply the necessary updates.
*   **Lack of critical ITSM information:**  Patch management systems often lack crucial information like known issues, failure rates, or crash data associated with specific patches.  This makes it hard to assess the risk of applying a patch.
*   **Need for mitigation information:** When patches cannot be applied immediately (due to known issues or other constraints), there's a need for readily available information about mitigations and workarounds.

This project aims to build a solution that addresses these problems by providing a centralized, correlated, and easily queryable source of patch intelligence.

## Goals

1.  **Collect Patch Information:** Gather patch data for popular application libraries.
2.  **Correlate Data:** Link patch information with CVEs and CPEs.
3.  **Build a Knowledge Graph:** Create an n-n knowledge graph representing the relationships between CVEs, CPEs, and patch information.

## Specifications

The system uses ArangoDB as a graph database to store the collected and correlated data.  The core data structure includes:

*   **Packages:** Representing software packages (e.g., `express` for npm).
*   **Versions:** Representing specific versions of a package (e.g., `express-4.17.1`).
*   **CVEs:** Representing known vulnerabilities (e.g., `CVE-2023-12345`).

Relationships:

*   **`hasVersion`:** Connects a `Package` node to its `Version` nodes.
*   **`vulnerableTo`:** Connects a `Version` node to the `CVE` nodes representing vulnerabilities that affect that version.

The system fetches data from:

*   **npm Registry API:** For npm package information.
*   **NVD (National Vulnerability Database) API:** For CVE information.

## Data Model

The ArangoDB database contains the following collections:

*   **`Packages`:**
    *   `_key`: Unique identifier (package name, or package name + version).
    *   `name`: Package name (e.g., "express").
    *   `version` (only for version documents): Version string (e.g., "4.17.1").
    *   `cpe` (only for version documents):  Generated CPE string.
    *   `tarball` (only for version documents): URL to download the package.
*   **`CVEs`:**
    *   `_key`: CVE ID (e.g., "CVE-2023-12345").
    *   `cve_id`: CVE ID.
    *   `description`:  Description of the vulnerability.

Edges:

*   **`hasVersion`:** Connects `Packages` to `Packages` (package to version).  Source: `Packages/{package_name}`, Target: `Packages/{package_name}-{version}`.
*   **`vulnerableTo`:** Connects `Packages` (version) to `CVEs`. Source: `Packages/{package_name}-{version}`, Target: `CVEs/{cve_id}`.

## Dependencies

*   Python 3.7+
*   ArangoDB (tested with Docker installation)
*   Python Libraries:
    *   `python-arango`
    *   `requests`
    *   `beautifulsoup4` (currently not used, but listed in `requirements.txt`)
    *   `pandas` (currently not used, but listed in `requirements.txt`)
    *   `python-dotenv`

## Installation and Setup

1.  **Install ArangoDB:**
    *   **Recommended: Use Docker:**

        ```bash
        docker pull arangodb
        docker run -d -p 8529:8529 -e ARANGO_ROOT_PASSWORD=your_strong_password arangodb/arangodb:latest
        ```

        Replace `your_strong_password` with a strong password.  This will run ArangoDB in a Docker container, making it easy to manage and isolated from your system. Alternatively, you can use the provided `docker-compose.yml` file to run ArangoDB with persistent storage:
        ```
        docker compose up -d
        ```
    *   **Alternative: Native Installation:** Follow the official ArangoDB installation instructions for your operating system: [https://www.arangodb.com/download/](https://www.google.com/url?sa=E&source=gmail&q=https://www.arangodb.com/download/)

2.  **Create Database and Collections:**
    *   Access the ArangoDB web interface (usually at `http://localhost:8529`).
    *   Log in with the `root` user and the password you set.
    *   Create a database named `PatchIntelDB`.
    *   Within `PatchIntelDB`, create two collections:
        *   `Packages` (Document type)
        *   `CVEs` (Document type)
     * Within `PatchIntelDB`, create a graph named `PackageGraph` and add edge definitions for `hasVersion` and `vulnerableTo` as described above.

3.  **Clone the Repository:**

    ```bash
    git clone <your_repository_url>
    cd <your_repository_name>
    ```

4.  **Create a Virtual Environment (Recommended):**

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    .venv\Scripts\activate  # Windows
    ```

5.  **Install Python Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

6.  **Create a `.env` File:**

    *   Create a file named `.env` in the project's root directory.
    *   Add your NVD API key to the `.env` file:

        ```
        NVD_API_KEY=YOUR_NVD_API_KEY
        ```

        Replace `YOUR_NVD_API_KEY` with your actual NVD API key (obtained from [https://nvd.nist.gov/developers/request-an-api-key](https://www.google.com/url?sa=E&source=gmail&q=https://nvd.nist.gov/developers/request-an-api-key)).  *Do not* put quotes around the key.

7. **Add `.env` to `.gitignore`.**

## Running the Script

```bash
python store_data.py
