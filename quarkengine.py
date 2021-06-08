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
        for crime in data['crimes']:
            dic_report_crime["{0}".format(crime["crime"])] = ResultSection("{0}".format(crime), parent = crimes_section)
            dic_report_crime["{0}".format(crime["crime"])].add_line("confidence level : {0}".format(crime["confidence"]))
            dic_report_crime["{0}".format(crime["crime"])].add_line("weight : {0}".format(crime["weight"]))

            if crime['permissions']:
                perm_section = ResultSection("permissions associated with the crime", parent = dic_report_crime["{0}".format(crime["crime"])])
                for permission in crime['permissions']:
                    dic_report_crime["{0}".format(crime["crime"])].add_line(permission)

            if crime['native_api']:
                native_api_section = ResultSection("native_api", parent = dic_report_crime["{0}".format(crime["crime"])])
                for api in crime["native_api"]:
                    dic_report_crime["{0}".format(crime["crime"])].add_line("class : {0}".format(api["class"]))
                    dic_report_crime["{0}".format(crime["crime"])].add_line("mathod : {0}".format(api["method"])) 
        result.add_section(crimes_section)