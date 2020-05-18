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
client = pymongo.MongoClient("mongodb+srv://siyan:UBC_CPSC_2020@fs-ahm8n.mongodb.net/test?retryWrites=true&w=majority")
db = client.test
mycol = db["inventory"]

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('file_upload.html')

class UploadHandler(tornado.web.RequestHandler):
    def post(self):
        # retrieve file from html
        file = self.request.files['fileToUpload'][0]
        file_sha256 = self.compute_sha256(file['body'])
        # create necessary folders on disk
        if not os.path.exists("uploads"):
            os.makedirs("uploads")
        if not os.path.exists("uploads/file_metadata.txt" ):
            file_metadata = open("uploads/file_metadata.txt", 'w+')
        # check if file report is on disk
        existAlready = False
        with open("uploads/file_metadata.txt", "r") as f:
            lines = f.readlines()
            for line in lines:
                if str(file_sha256) in line:
                    existAlready = True
                    break
        
        if not existAlready:
            print("upload and scan")
            self.upload_to_scan(file)

        print("retrieve from disk")
        # report = self.retrieve_from_disk(str(file_sha256))
        report = self.retrieve_from_db(str(file_sha256))
        print(report)
        names = "".join(report.detections_names)
        self.render('report.html', sha256=report.hash_value[0], md5=report.hash_value[1], time=report.scan_data, num_engines_detected=report.num_engines_detected, names=names)
        self.clean_up(str(file_sha256))


    def clean_up(self, current_hash):
        seconds_in_day = 24 * 60 * 60
        gap = SHELF_LIFE
        curr_date_time = datetime.datetime.now()
        lines_to_delete = []
        line_to_update = -1
        content_line_to_update = ""
        line_hash = {}
        with open('uploads/file_metadata.txt') as myFile:
            for num, line in enumerate(myFile, 1):
                hash_and_date = line.split("+")
                hash_value = hash_and_date[0]
                date = hash_and_date[1][:-2]
                prev_date_time = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M:%S.%f")
                diff_date_time = curr_date_time - prev_date_time
                diff = diff_date_time.days * seconds_in_day + diff_date_time.seconds
                if hash_value == current_hash:
                    line_to_update = num
                    content_line_to_update = hash_value + "+" + str(curr_date_time) + "\n"
                elif diff > gap:
                    lines_to_delete.append(num)
                    line_hash[num] = hash_value
                else:
                    pass

        with open("uploads/file_metadata.txt", "r") as f:
            lines = f.readlines()

        with open('uploads/file_metadata.txt', "w") as file:
            for num, line in enumerate(lines, 1):
                if num == line_to_update:
                    print("update datetime for current file")
                    file.write(content_line_to_update)
                elif num not in lines_to_delete:
                    file.write(line)
                else:
                    os.remove("uploads/" + line_hash[num] + ".json")

    def retrieve_from_db(self, file_sha256):
        myquery = { "resource": str(file_sha256) }
        mydoc = mycol.find_one(myquery)
        report = parser.Report(mydoc)
        print(report.detections_names)
        return report

    # def retrieve_from_disk(self, file_sha256):
    #     with open("uploads/"+ file_sha256 +".json", 'rb') as file:
    #         report_obj = pickle.load(file)
    #         report = parser.Report(report_obj)
    #         return report

    def upload_to_scan(self, file):
        try:
            url = BASE_URL + 'scan'
            params= {'apikey': API_KEY}
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
            date = str(datetime.datetime.now())
            res_json = open('uploads/file_metadata.txt', 'a+')
            self.get_report(resource)
            res_json.write(resource + "+" + date + "\n")
            res_json.close()
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
        res_json = open("uploads/" + resource + ".json", 'wb')
        
        #### insert report into the database ###
        mycol.insert_one(data)
        ########################################

        pickle.dump(data, res_json, pickle.HIGHEST_PROTOCOL)
        res_json.close()
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