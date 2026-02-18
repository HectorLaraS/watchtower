import re
from datetime import datetime


my_var = "Detected Entry: 2025-02-09 07:09:52 call_type: I alert_id: 170172 data_center: CTMlinux memname: BPHXCTLM.ksh order_id: 1oje6 severity: V status: Not_Noticed send_time: 20250209070952 last_user: last_time: message: Ended not OK run_as: cntrlm sub_application: KXWHD_PROD-GP application: KXWHD job_name: KMWHD001 host_id: kcmcsappp alert_type: R closed_from_em: ticket_number: run_counter: 00002"

def obtener_entre(texto, palabra_anterior, palabra_siguiente):
    # Expresión regular para encontrar una palabra entre dos palabras específicas
    patron = rf"{palabra_anterior}\s+(\S+)\s+{palabra_siguiente}"
    match = re.search(patron, texto)

    return match.group(1) if match else None

def obtener_valor(log, clave):
    # Expresión regular para encontrar "clave: valor" hasta la siguiente clave
    patron = rf"{clave}:\s*([\S]+)(?=\s+\S+:|$)"
    match = re.search(patron, log)

    return match.group(1) if match else None

def obtener_fecha(log, clave):
    # Expresión regular para capturar una fecha en formato YYYY-MM-DD HH:MM:SS
    patron = rf"{clave}:\s*(\d{{4}}-\d{{2}}-\d{{2}}\s\d{{2}}:\d{{2}}:\d{{2}})"
    match = re.search(patron, log)

    return match.group(1) if match else None

def obtener_despues_de(texto, palabra_clave):
    # Expresión regular para encontrar la palabra después de la clave
    patron = rf"{palabra_clave}:\s*(\S+)"
    match = re.search(patron, texto)

    return match.group(1) if match else None

def obtener_texto_entre(texto, palabra_inicio, palabra_fin):
    # Expresión regular para capturar el texto entre palabra_inicio y palabra_fin
    patron = rf"{palabra_inicio}:\s*(.+?)\s*{palabra_fin}:"
    match = re.search(patron, texto)

    return match.group(1).strip() if match else None

def get_database_information(my_working_file: str):
    lst_output_information = []
    for line in my_working_file:
        work_line = line.strip()
        current_queue_info = work_line.split(",")
        res = f"{current_queue_info[0].strip()},{current_queue_info[1].strip()},{current_queue_info[2].strip()},{current_queue_info[3].strip()}"
        lst_output_information.append(res)
    return lst_output_information


def is_on_database(lst_database_info: list, affected_controlm:str) -> list:
    if type(affected_controlm) == type(None):
        affected_controlm =  "tmp"
    res: list = []
    is_on_database = False
    for current_queue in lst_database_info:
        current_queue_info = current_queue.split(",")
        if current_queue_info[1] == affected_controlm.upper():
            is_on_database = True
            res = [current_queue_info[0],current_queue_info[1],current_queue_info[2],current_queue_info[3],is_on_database]
        if is_on_database:
            pass
        else:
            res = [current_queue_info[0],current_queue_info[1], "Z-HPO-00A-SEV4",4,is_on_database]
    return res

def assign_priority(sev: str):
    res = "Priority 3"
    if sev == "3": 
        res = "Priority 2"
    elif sev == "4":
        res = "Priority 3"
    elif sev == "5":
        res = "Priority 4"
    return res

def fun_need_alert(id: str) -> bool:
    result = True
    with open("ids_alerted.log", "r") as log_ids:
        for line in log_ids:
            if id == line.strip():
                result = False
    return result

def string_to_date(str_date: str): 
    return datetime.strptime(str_date,"%Y-%m-%d %H:%M:%S")

def is_on_past(fecha: str) -> bool:
    fecha_dt = string_to_date(fecha)
    need_alert: bool = False
    today = datetime.now().date()
    alert_date = fecha_dt.date()
    if alert_date == today:
        need_alert = True
    return need_alert

if __name__ == "__main__":

    # Ejemplos de prueba
    log1 = "llave1: valor1 llave2: valor2"
    log2 = "evento: inicio trigger: alerta nivel: alto"
    log3 = "usuario: Juan edad: 25 ciudad: Madrid"

    print(obtener_fecha(my_var, "Detected Entry")) #2025-02-09 07:09:52
    print(obtener_entre(my_var, "call_type:", "alert_id:"))  # "I"
    print(obtener_entre(my_var, "alert_id:", "data_center:"))  # "170172"
    print(obtener_entre(my_var, "data_center:", "memname:"))  # "CTMlinux"
    print(obtener_entre(my_var, "memname:", "order_id:"))  # "BPHXCTLM.ksh"
    print(obtener_entre(my_var, "order_id:", "severity:"))  # "1oje6"
    print(obtener_entre(my_var, "severity:", "status:"))  # "V"
    print(obtener_entre(my_var, "status:", "send_time:"))  # "Not_Noticed"
    print(obtener_entre(my_var, "send_time:", "last_user:"))  # "20250209070952"
    print(obtener_entre(my_var, "last_user:", "last_time:"))  # "None"
    print(obtener_entre(my_var, "last_time:", "message:"))  # "None"
    print(obtener_texto_entre(my_var, "message", "run_as"))  # "NOT WORKING"
    print(obtener_entre(my_var, "run_as:", "sub_application:"))  # "cntrlm"
    print(obtener_entre(my_var, "sub_application:", "application:"))  # "KXWHD_PROD-GP"
    print(obtener_entre(my_var, "application:", "job_name:"))  # "KXWHD"
    print(obtener_entre(my_var, "job_name:", "host_id:"))  # "KMWHD001"
    print(obtener_entre(my_var, "host_id:", "alert_type:"))  # "kcmcsappp"
    print(obtener_entre(my_var, "alert_type:", "closed_from_em:"))  # "R"
    print(obtener_entre(my_var, "closed_from_em:", "ticket_number:"))  # "None"
    print(obtener_entre(my_var, "ticket_number:", "run_counter:"))  # "None"
    print(obtener_despues_de(my_var, "run_counter"))  # "None"

    print("*** Message: ***")
    print(obtener_texto_entre(my_var, "message", "run_as"))  # "NOT WORKING"

