#This file is part of ElectricEye.
#SPDX-License-Identifier: Apache-2.0

#Licensed to the Apache Software Foundation (ASF) under one
#or more contributor license agreements.  See the NOTICE file
#distributed with this work for additional information
#regarding copyright ownership.  The ASF licenses this file
#to you under the Apache License, Version 2.0 (the
#"License"); you may not use this file except in compliance
#with the License.  You may obtain a copy of the License at

#http://www.apache.org/licenses/LICENSE-2.0

#Unless required by applicable law or agreed to in writing,
#software distributed under the License is distributed on an
#"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#KIND, either express or implied.  See the License for the
#specific language governing permissions and limitations
#under the License.
import json
from processor.outputs.output_base import ElectricEyeOutput

@ElectricEyeOutput
class StdoutProvider(object):
    __provider__ = "stdout"

    def write_findings(self, findings: list, output_file: str, **kwargs):
        checkedIds = []

        for finding in findings:
            print(finding)
            '''if finding["Id"] not in checkedIds:
                checkedIds.append(finding["Id"])
                print(json.dumps(finding,default=str))
            else:
                continue'''
            
        return True