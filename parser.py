class Report:
    def __init__(self, data):
        self.hash_value = ['sha256: ' + data['sha256'], 'md5: ' + data['md5']]
        self.scan_data = data['scan_date']
        self.detections_names = []
        self.num_engines_detected = 0
        for s in data['scans']:
            if data['scans'][s]['detected']:
                self.detections_names.append(data['scans'][s]['result'])
                self.num_engines_detected += 1

