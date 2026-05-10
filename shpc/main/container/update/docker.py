__author__ = "Vanessa Sochat"
__copyright__ = "Copyright 2021-2025, Vanessa Sochat"
__license__ = "MPL 2.0"

import os
import re
import time

import requests

from shpc.logger import logger


class DockerImage:

    """
    A thin client for getting metadata about an image.
    """

    def __init__(self, container_name):
        self.container_name = container_name

        # might not last forever, but we can use it for now
        self.apiroot = "https://crane.ggcr.dev"

    def get_request(self, url):
        """
        Perform a get request, expecting status code 200.
        """
        response = requests.get(url)

        # Try to retry once if rate limited
        if response.status_code == 429:
            retry_seconds = response.headers.get("Retry-After", "unknown")
            logger.warning("Rate limit hit for %s, retrying after %s seconds" % (url, retry_seconds))
            time.sleep(int(retry_seconds) + 1)
            response = requests.get(url)

        if response.status_code == 404:
            raise ValueError(f"Request to {url} returned 404.")
        if response.status_code != 200:
            logger.exit("Issue with request %s. Status code: %d" % (url, response.status_code))

        return response

    def tags(self):
        """
        Get image tags.
        """

        url = "%s/ls/%s" % (self.apiroot, self.container_name)
        response = self.get_request(url)
        tags = [x.strip() for x in response.text.split("\n") if x.strip()]
        # Don't include tags for vex or sbom
        tags = [x for x in tags if not re.search("[.](sbom|vex)$", x)]
        return tags

    def manifest(self, tag):
        url = "%s/manifest/%s:%s" % (self.apiroot, self.container_name, tag)
        response = self.get_request(url)
        return response.json()

    def digest(self, tag):
        url = "%s/digest/%s:%s" % (self.apiroot, self.container_name, tag)
        response = self.get_request(url)
        if "could not parse reference" in response:
            logger.exit("Issue getting digest: %s" % response)
        if "unsupported status" in response:
            logger.exit("Issue getting digest: %s" % response)
        if "MANIFEST_UNKNOWN" in response.text:
            logger.exit(
                f"The tag {tag} you provided is not known. Check that it and the container both exist."
            )
        return response.text

    def config(self):
        url = "%s/config/%s" % (self.apiroot, self.container_name)
        return self.get_request(url).json()

class QuayDockerImage(DockerImage):

    """
    A thin client for getting metadata about an image on Quay.
    """

    def __init__(self, container_name):
        super().__init__(container_name)
        self.apiroot = "https://quay.io/api/v1/repository/%s/tag"
        self.tag_response = None

    def _query_tag_api(self):
        """
        Custom endpoint to handle quay and pagination.
        """
        repository = self.container_name.replace("quay.io/", "", 1)
        page = 1
        tags = []
        has_more = True
        while has_more:
            url = f"https://quay.io/api/v1/repository/{repository}/tag/?limit=100&page={page}"
            response = self.get_request(url).json()
            new_tags = [
                x for x in response.get("tags", {}) if x.get("name")
            ]
            tags.extend(new_tags)
            has_more = response.get("has_additional") is True
            page += 1
        return tags
    
    def tags(self):
        if self.tag_response is None:
            self.tag_response = self._query_tag_api()
        tags = [x["name"] for x in self.tag_response]
        # Don't include tags for vex or sbom
        tags = [x for x in tags if not re.search("[.](sbom|vex)$", x)]
        return tags

    def digest(self, tag):
        if self.tag_response is not None:
            for tag_info in self.tag_response:
                if tag_info["name"] == tag:
                    return tag_info["manifest_digest"]
        try:
            tag_response = self._query_tag_api(tag=tag)
            for tag_info in tag_response:
                if tag_info["name"] == tag:
                    return tag_info["manifest_digest"]
        except ValueError:
            logger.warning(
                f"The tag {tag} you provided is not known. Check that it and the container both exist."
            )
            return None
class DockerHubImage(DockerImage):

    """
    A thin client for getting metadata about an image on DockerHub.
    """

    def __init__(self, container_name):
        super().__init__(container_name)
        container_name_array = container_name.replace("docker.io/", "", 1).split("/")
        if len(container_name_array) == 1:
            self.container_name = "library/%s" % container_name_array[0]
        elif len(container_name_array) == 2:
            self.container_name = "%s/%s" % (
                container_name_array[0],
                container_name_array[1],
            )
        self.apiroot = "https://hub.docker.com/v2/repositories"

        self.tag_response = None

    def _query_tag_api(self, tag=None):
        tag_responses = []
        if tag is None:
            url = "%s/%s/tags?page_size=%s" % (self.apiroot, self.container_name, 100)
        else:
            url = "%s/%s/tags/%s" % (self.apiroot, self.container_name, tag)

        while True:
            response = self.get_request(url)
            tag_responses.extend(response.json()["results"])
            url = response.json().get("next")
            if url is None:
                break
        return tag_responses

    def tags(self):
        if self.tag_response is None:
            self.tag_response = self._query_tag_api()
        tags = [x["name"] for x in self.tag_response]
        # Don't include tags for vex or sbom
        tags = [x for x in tags if not re.search("[.](sbom|vex)$", x)]
        return tags

    def digest(self, tag):
        tag_dict = None
        print(tag)
        if self.tag_response is not None:
            for tag_info in self.tag_response:
                if tag_info["name"] == tag:
                    tag_dict = tag_info
                    break
        else:
            tag_response = self._query_tag_api(tag=tag)
            for tag_info in tag_response:
                if tag_info["name"] == tag:
                    tag_dict = tag_info
                    break
                
        if tag_dict:
            digest = tag_dict.get("digest", None)
            if digest:
                return digest
            else:
                return tag_dict.get("images", [{}])[0].get("digest", "unknown")
        logger.exit(
            f"The tag {tag} you provided is not known. Check that it and the container both exist."
        )

class NGCImage(DockerImage):

    """
    A thin client for getting metadata about an image on NGC.
    """

    def __init__(self, container_name):
        super().__init__(container_name)
        self.apiroot = None
        self.container_name = container_name.replace("nvcr.io/", "", 1)

        from ngcsdk import Client
        self.client = Client()
        self.client.configure(
            os.environ.get("SHPC_NGC_API_KEY"), 
        )

        self.tag_response = None
    
    def _query_tag_api(self):
        image_list = self.client.registry.image.list(self.container_name)
        return [image.toDict() for image in image_list]
    
    def tags(self):
        if self.tag_response is None:
            self.tag_response = self._query_tag_api()
        tags = [x["tag"] for x in self.tag_response]
        # Don't include tags for vex or sbom
        tags = [x for x in tags if not re.search("[.](sbom|vex)$", x)]
        return tags

    def digest(self, tag):
        if self.tag_response is not None:
            for tag_info in self.tag_response:
                if tag_info["tag"] == tag:
                    return tag_info["digest"]
        tag_response = self._query_tag_api(tag=tag)
        for tag_info in tag_response:
            if tag_info["tag"] == tag:
                return tag_info["digest"]
        logger.exit(
            f"The tag {tag} you provided is not known. Check that it and the container both exist."
        )
