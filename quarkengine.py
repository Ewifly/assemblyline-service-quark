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
            res_sec = ResultSection("A file containing raw Json output was generated")
            request.add_supplementary(quark_out, "quark_out", "These are quark Results as a JSON file")
            self.run_analysis(quark_out, result)
            result.add_section(res_sec)
        request.result = result


    def run_analysis(self, quark_out, result):
        with open(quark_out) as f:
            data = json.load(f)

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
                dic_report_crime["{0}".format(crimes_array[i]["crime"])] = ResultSection("{0}".format(crimes_array[i]["crime"]), parent = crimes_section)
                dic_report_crime["{0}".format(crimes_array[i]["crime"])].add_line("confidence level : {0}".format(crimes_array[i]["confidence"]))
                dic_report_crime["{0}".format(crimes_array[i]["crime"])].add_line("weight : {0}".format(crimes_array[i]["weight"]))

                if len(crimes_array[i]['permissions']) > 0:
                    perm_section = ResultSection("permissions associated with the crime", parent = dic_report_crime["{0}".format(crimes_array[i]["crime"])])
                    for permission in crimes_array[i]['permissions']:
                        perm_section.add_line(permission)

                if len(crimes_array[i]['native_api']) > 0:
                    native_api_section = ResultSection("native_api", parent = dic_report_crime["{0}".format(crimes_array[i]["crime"])])
                    for api in crimes_array[i]["native_api"]:
                        native_api_section.add_line("class : {0}".format(api["class"]))
                        native_api_section.add_line("method : {0}".format(api["method"])) 
        result.add_section(crimes_section)