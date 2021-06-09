import json
import os
from subprocess import Popen, call
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic

class QuarkEngine(ServiceBase):
    def __init__(self, config=None):
        super(QuarkEngine, self).__init__(config)

    def start(self):
        self.log.info(f"start() from {self.service_attributes.name} service called")

    def execute(self, request):
        result = Result()
        apk = request.file_path
        filename = os.path.basename(apk)
        quark_out = os.path.join(self.working_directory, 'quark_out')

        if request.get_param('generate_graphs'):
            qu = Popen(["quark", "-a", apk, "-g", "-o", quark_out, "-r", "/opt/al_support/quark-rules"])
            qu.communicate()
        else:
            qu = Popen(["quark", "-a", apk, "-o", quark_out, "-r", "/opt/al_support/quark-rules"])
            qu.communicate()

        if os.path.exists(quark_out):
            self.run_analysis(quark_out, result)
            request.add_supplementary(quark_out, "quark_out", "These are quark Results as a JSON file")
        request.result = result


    def run_analysis(self, quark_out, result):
        with open(quark_out) as f:
            data = json.load(f)

        self.manage_threat_level(data, result)
        dic_report_crime = {}
        crimes_section = ResultSection("Crimes detected")
        crimes_array = []
        counter = 0
        for i in range(len(data['crimes'])):
            if data['crimes'][i]['confidence'] == "80%":
                crimes_array.insert(len(crimes_array) - counter, data['crimes'][i])
            if data['crimes'][i]['confidence'] == "100%":
                crimes_array.insert(0, data['crimes'][i])
            if data['crimes'][i]['confidence'] == "60%":
                counter += 1
                crimes_array.insert(len(crimes_array), data['crimes'][i])

        for i in range(len(crimes_array)):
            if crimes_array[i]['confidence'] in ["60%", "80%", "100%"]: 
                dic_report_crime["{0}".format(crimes_array[i]["crime"])] = ResultSection("{0}".format(crimes_array[i]["crime"]), parent = crimes_section, body_format=BODY_FORMAT.MEMORY_DUMP)
                dic_report_crime["{0}".format(crimes_array[i]["crime"])].add_line("confidence level : {0}".format(crimes_array[i]["confidence"]))

                if len(crimes_array[i]['permissions']) > 0:
                    perm_section = ResultSection("permissions associated with the crime", parent = dic_report_crime["{0}".format(crimes_array[i]["crime"])], body_format=BODY_FORMAT.MEMORY_DUMP)
                    for permission in crimes_array[i]['permissions']:
                        perm_section.add_line(permission)

                if len(crimes_array[i]['native_api']) > 0:
                    native_api_section = ResultSection("native_api", parent = dic_report_crime["{0}".format(crimes_array[i]["crime"])], body_format=BODY_FORMAT.MEMORY_DUMP)
                    for api in crimes_array[i]["native_api"]:
                        native_api_section.add_line("class : {0}".format(api["class"]))
                        native_api_section.add_line("method : {0}".format(api["method"]))
            dic_report_crime["{0}".format(crimes_array[i]["crime"])].add_line("   ")

        result.add_section(crimes_section)

    def manage_threat_level(self, data, result):
        if data['threat_level'] == 'Low_Risk':
            threat_section = ResultSection("threat level : {0}".format(data['threat_level']), heuristic = Heuristic(1))
        if data['threat_level'] == 'Moderate Risk':
            threat_section = ResultSection("threat level : {0}".format(data['threat_level']), heuristic = Heuristic(2))
        if data['threat_level'] == 'High Risk':
            threat_section = ResultSection("threat level : {0}".format(data['threat_level']), heuristic = Heuristic(3))
        result.add_section(threat_section)