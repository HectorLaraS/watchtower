import os
import sys
from  controlm_help_functions import *
from datetime import datetime


new_entry_1 = sys.argv[1]
new_entry_2 = sys.argv[2]
new_entry_3 = sys.argv[3]
new_entry_4 = sys.argv[4]
log_file_to_store = "controlm_log_alerts.txt"
db_controlm_file = "controlm_db.txt"
var_need_alert = True

input_var = f"Var_1: {new_entry_1} Var_2:{new_entry_2} Var_3:{new_entry_3} Var_4:{new_entry_4}\n"
log_file = open("log_controlm_sandbox.txt","a")

#Variables for log on ServiceNow

tmp_app_name = new_entry_1
tmp_source_path = new_entry_2
tmp_server = new_entry_3
tmp_detected_entry = obtener_fecha(new_entry_4, "Detected Entry")
tmp_call_type = obtener_entre(new_entry_4, "call_type:", "alert_id:")
tmp_alert_id = obtener_entre(new_entry_4, "alert_id:", "data_center:")
tmp_data_center = obtener_entre(new_entry_4, "data_center:", "memname:")
tmp_memname = obtener_entre(new_entry_4, "memname:", "order_id:")
tmp_order_id = obtener_entre(new_entry_4, "order_id:", "severity:")
tmp_severity = obtener_entre(new_entry_4, "severity:", "status:")
tmp_status = obtener_entre(new_entry_4, "status:", "send_time:")
tmp_send_time = obtener_entre(new_entry_4, "send_time:", "last_user:")
tmp_last_user = obtener_entre(new_entry_4, "last_user:", "last_time:")
tmp_last_time = obtener_entre(new_entry_4, "last_time:", "message:")
tmp_message = obtener_texto_entre(new_entry_4, "message", "run_as")
tmp_run_as = obtener_entre(new_entry_4, "run_as:", "sub_application:")
tmp_sub_application = obtener_entre(new_entry_4, "sub_application:", "application:")
tmp_application = obtener_entre(new_entry_4, "application:", "job_name:")
tmp_job_name = obtener_entre(new_entry_4, "job_name:", "host_id:")
tmp_host_id = obtener_entre(new_entry_4, "host_id:", "alert_type:")
tmp_alert_type = obtener_entre(new_entry_4, "alert_type:", "closed_from_em:")
tmp_closed_from_em  = obtener_entre(new_entry_4, "closed_from_em:", "ticket_number:")
tmp_ticket_number = obtener_entre(new_entry_4, "ticket_number:", "run_counter:")
tmp_run_counter = obtener_despues_de(new_entry_4, "run_counter")


log_file.writelines(input_var)
log_file.close()

#Define Priority

controlm_file = open(db_controlm_file,"r")
lst_ctrlm = get_database_information(controlm_file)
tmp_element = is_on_database(lst_ctrlm,tmp_job_name)
tmp_sn_priority = assign_priority(tmp_element[3])
tmp_hpo_assignment_group = tmp_element[2]

need_alert_date_base = is_on_past(tmp_detected_entry)

#Add alert_id to log
if fun_need_alert(tmp_alert_id) and need_alert_date_base:
    with open("ids_alerted.log","a") as id_logs:
        id_logs.writelines(f"{tmp_alert_id}\n")
else:
    var_need_alert = False
    print(f"Alert: {tmp_alert_id} out of time range")

str_log_entry = f"{tmp_server},{tmp_job_name},{tmp_detected_entry},call_type:{tmp_call_type} alert_id:{tmp_alert_id} data_center:{tmp_data_center} memname:{tmp_memname} order_id:{tmp_order_id} severity:{tmp_severity} status:{tmp_status} send_time:{tmp_send_time} last_user:{tmp_last_user} last_time:{tmp_last_time} message:{tmp_message} run_as:{tmp_run_as} sub_application:{tmp_sub_application} application:{tmp_application} job_name:{tmp_job_name} host_id:{tmp_host_id} alert_type:{tmp_alert_type} closed_from_em:{tmp_closed_from_em} ticket_number:{tmp_ticket_number} run_counter:{tmp_run_counter}, {tmp_sn_priority}, {tmp_hpo_assignment_group}"
str_log_entry_dynatrace= f"controlm_server:{tmp_server},job_name:{tmp_job_name},detected_entry:{tmp_detected_entry},call_type:{tmp_call_type},alert_id:{tmp_alert_id},data_center:{tmp_data_center},memname:{tmp_memname},order_id:{tmp_order_id},severity:{tmp_severity},status:{tmp_status},send_time:{tmp_send_time},last_user:{tmp_last_user},last_time:{tmp_last_time},message:{tmp_message},run_as:{tmp_run_as},sub_application:{tmp_sub_application},application:{tmp_application},job_name:{tmp_job_name},host_id:{tmp_host_id},alert_type:{tmp_alert_type},closed_from_em:{tmp_closed_from_em},ticket_number:{tmp_ticket_number},run_counter:{tmp_run_counter},Incident_Priority:{tmp_sn_priority},AssignmentGroupCode:{tmp_hpo_assignment_group}"

if "BSNAGT_MESSAGES_PULL" in str_log_entry:
    tmp_sn_priority = "Priority 4"
    str_log_entry = f"{tmp_server},{tmp_job_name},{tmp_detected_entry},call_type:{tmp_call_type} alert_id:{tmp_alert_id} data_center:{tmp_data_center} memname:{tmp_memname} order_id:{tmp_order_id} severity:{tmp_severity} status:{tmp_status} send_time:{tmp_send_time} last_user:{tmp_last_user} last_time:{tmp_last_time} message:{tmp_message} run_as:{tmp_run_as} sub_application:{tmp_sub_application} application:{tmp_application} job_name:{tmp_job_name} host_id:{tmp_host_id} alert_type:{tmp_alert_type} closed_from_em:{tmp_closed_from_em} ticket_number:{tmp_ticket_number} run_counter:{tmp_run_counter}, {tmp_sn_priority}, {tmp_hpo_assignment_group}"

if "severity:V" in str_log_entry and var_need_alert:
    log_file = open(log_file_to_store,"a")
    log_file.writelines(f"{str_log_entry} \n")
    log_file.close()
    with open("alerts_to_work.log","a") as my_file:
        my_file.writelines(f"{str_log_entry_dynatrace} \n")
        
else:
    print("Not Need Alert")

print(str_log_entry_dynatrace)
