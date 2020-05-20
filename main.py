import datetime

import tornado.httpserver, tornado.ioloop, tornado.options, tornado.web, os.path, random, string
from requests.exceptions import HTTPError
import json, os, time
import hashlib
import parser
import pickle
import requests
import pymongo

BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'
API_KEY = 'ff75f48440f980444e349cd8327da712fa2dfc2eec455cb6c894734f636b7a67'
PUBLIC_API_SLEEP_TIME = 30
SHELF_LIFE = 24 * 60 * 60
client = pymongo.MongoClient("mongodb+srv://laura:UBC_CPSC_2020@fs-ahm8n.mongodb.net/test?retryWrites=true&w=majority")
db = client.test
mycol = db["inventory"]
print(mycol)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('file_upload.html')


class UploadHandler(tornado.web.RequestHandler):
    def post(self):
        # retrieve file from html
        file = self.request.files['fileToUpload'][0]
        file_sha256 = self.compute_sha256(file['body'])
        report = self.retrieve_from_db(str(file_sha256))
        if not report:
            print("upload and scan")
            self.upload_to_scan(file)

        print("retrieve from db")
        report = self.retrieve_from_db(str(file_sha256))

        print(report)
        names = "".join(report.detections_names)
        self.render('report.html', sha256=report.hash_value[0], md5=report.hash_value[1], time=report.scan_data,
                    num_engines_detected=report.num_engines_detected, names=names)


    def retrieve_from_db(self, file_sha256):
        myquery = {"resource": str(file_sha256)}
        mydoc = mycol.find_one(myquery)
        if mydoc is None:
            return None
        report = parser.Report(mydoc)
        print(report.detections_names)
        return report


    def upload_to_scan(self, file):
        try:
            url = BASE_URL + 'scan'
            params = {'apikey': API_KEY}
            file_content = {'file': ('output_file', file['body'])}
            response = requests.post(url, files=file_content, params=params)
            # If the response was successful, no Exception will be raised
            response.raise_for_status()
        except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')
        except Exception as err:
            print(f'Other error occurred: {err}')
        else:
            data = response.json()
            # send to mongodb
            resource = data["resource"]
            self.get_report(resource)
            print('Success!')

    def compute_sha256(self, file):
        """
        compute sha256 of the file
        """
        if file:
            m = hashlib.sha256()
            m.update(file)
            return m.hexdigest()
        return 0

    def get_report(self, resource):
        url = BASE_URL + 'report'
        params = {'apikey': API_KEY, 'resource': resource}
        response = requests.get(url, params=params)
        data = response.json()
        while data['response_code'] is not 1:
            time.sleep(PUBLIC_API_SLEEP_TIME)
            print('report not finished:', data)
            data = requests.get(url, params=params).json()
        mycol.insert_one(data)
        print('Success! Report generated')


class ActionHandler(tornado.web.RequestHandler):
    def get(self):
        print("button click")


def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/upload", UploadHandler),
        (r"/explicit_action_url/", ActionHandler)
    ])


if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
