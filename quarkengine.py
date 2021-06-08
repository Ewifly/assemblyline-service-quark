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
            qu = Popen(["quark", "-a", apk, "-g", "-t", "80", "-o", quark_out, "-r", "/opt/al_support/quark-rules"])
            qu.communicate()
        else:
            qu = Popen(["quark", "-a", apk, "-t", "80", "-o", quark_out, "-r", "/opt/al_support/quark-rules"])
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
        for i in range(len(data['crimes'])):
                dic_report_crime["{0}".format(data["crimes"][i]["crime"])] = ResultSection("{0}".format(data["crimes"][i]["crime"]), parent = crimes_section)
                dic_report_crime["{0}".format(data["crimes"][i]["crime"])].add_line("confidence level : {0}".format(data["crimes"][i]["confidence"]))
                dic_report_crime["{0}".format(data["crimes"][i]["crime"])].add_line("weight : {0}".format(data["crimes"][i]["weight"]))

                if len(data["crimes"][i]['permissions']) > 0:
                    perm_section = ResultSection("permissions associated with the crime", parent = dic_report_crime["{0}".format(data["crimes"][i]["crime"])])
                    for permission in data["crimes"][i]['permissions']:
                        dic_report_crime["{0}".format(data["crimes"][i]["crime"])].add_line(permission)

                if len(data["crimes"][i]['native_api']) > 0:
                    native_api_section = ResultSection("native_api", parent = dic_report_crime["{0}".format(data["crimes"][i]["crime"])])
                    for api in data["crimes"][i]["native_api"]:
                        dic_report_crime["{0}".format(data["crimes"][i]["crime"])].add_line("class : {0}".format(api["class"]))
                        dic_report_crime["{0}".format(data["crimes"][i]["crime"])].add_line("method : {0}".format(api["method"])) 
        result.add_section(crimes_section)