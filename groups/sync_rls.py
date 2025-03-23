#!/usr/bin/env python3
import glob
import json
import sys
from typing import List, Tuple, Dict, Set

import boto3
from redshift_connector import connect
from utils.aws import redshift

# Constantes necessárias
AWS_ACCOUNT_ID = "344729309528"
DATABASE_NAME = "vtex"
USERNAME = "root"
GROUPS_PATH = "../groups/"

# Modo dry-run para testes
IS_DRY_RUN = len(sys.argv) > 1 and sys.argv[1] == "--dry-run"
DRY_RUN_MSG = "[DRY RUN] " if IS_DRY_RUN else ""

rs_client = boto3.client("redshift-data")
sm_client = boto3.client("secretsmanager")

# Criacao de role no Redshift
SQL_CREATE_ROLE = 'CREATE ROLE "{role_name}";'


# executar queries usando o módulo redshift
def run_query(cluster_name: str, sql: str):
    return redshift.run_query(
        client=rs_client,
        cluster=cluster_name,
        database="vtex",
        user=USERNAME,
        sql=sql,
    )


def grant_role_to_user(role: str, username: str) -> None:
    sql = f'GRANT ROLE "{role}" TO {username};'
    print(f"{DRY_RUN_MSG}Granting role '{role}' to user {username}:")
    if not IS_DRY_RUN:
        run_query("prd-cluster-main", sql)


def ensure_role_exists(role_name: str) -> None:
    sql = SQL_CREATE_ROLE.format(role_name=role_name)
    try:
        print(f"{DRY_RUN_MSG}Ensuring role '{role_name}' exists")
        if not IS_DRY_RUN:
            run_query("prd-cluster-main", sql)
    except Exception as e:
        # Se a role já existir, podemos apenas imprimir uma mensagem e continuar.
        print(f"Role '{role_name}' may already exist: {e}")


# função de sanitização do nome da tabela para uso em nomes de policy
def sanitize_table_name(table_name: str) -> str:
    # Remove aspas e substitui pontos por underlines
    return table_name.replace('"', "").replace(".", "_")


# função para ler regras de RLS da tabela rls.rls_control
def get_rls_rules_from_redshift(cluster_name: str) -> List[Tuple[str, str, List[str]]]:
    if IS_DRY_RUN:
        # Dados dummy para testes locais
        return [
            ('"dev"."oms_silver"."orders_latest"', "hostname", ["lojafarm", "samsungbrshop"]),
            ('"dev"."payments_silver"."transaction_transitions"', "account", ["lojafarm", "samsungbrshop"]),
        ]
    sql = "SELECT table_name, column_name, allowed_values FROM dev.rls.data_storage"
    print(f"Executing SQL to get rules: {sql}")
    desc = run_query(cluster_name, sql)
    res = rs_client.get_statement_result(Id=desc.sql_id)
    rules = []
    for record in res["Records"]:
        table_name = record[0]["stringValue"]
        column_name = record[1]["stringValue"]
        allowed_values_csv = record[2]["stringValue"]
        allowed_values = [v.strip() for v in allowed_values_csv.split(",")]
        rules.append((table_name, column_name, allowed_values))
    return rules


# Função para aplicar as policies de RLS
def apply_rls_policies(cluster_name: str, table_to_group: Dict[str, str]) -> None:
    rules = get_rls_rules_from_redshift(cluster_name)
    processed_tables = set()  # Armazena tuplas (table_name, group_name)
    for table_name, column_name, allowed_values in rules:
        # obtem a role dinamicamente; se não existir, usa "rls" como padrão.
        group_name = table_to_group.get(table_name, "rls")
        sanitized_table_name = sanitize_table_name(table_name)
        policy_name = f"rls_policy_{group_name}_{sanitized_table_name}"
        values_str = ", ".join(f"'{v}'" for v in allowed_values)
        sql = f"""
        CREATE RLS POLICY {policy_name}
        WITH (hostname VARCHAR (256))
        USING (
            {column_name} IN ({values_str})
        );
        """
        print(f"{DRY_RUN_MSG}Applying policy for {table_name}:")
        print(sql)
        if not IS_DRY_RUN:
            run_query(cluster_name, sql)
        processed_tables.add((table_name, group_name))

    # Para cada tabela processada, gera os comandos para anexar a policy à role dinâmica e habilitar RLS
    for table_name, group_name in processed_tables:
        policy_name = f"rls_policy_{group_name}_{sanitize_table_name(table_name)}"
        attach_sql = f"ATTACH RLS POLICY {policy_name} ON {table_name} TO ROLE {group_name};"
        alter_sql = f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;"
        alter_sql_datasharing = f"ALTER TABLE {table_name} ROW LEVEL SECURITY OFF FOR DATASHARES;"
        print(f"{DRY_RUN_MSG}Attaching policy {policy_name} for {table_name} to role {group_name}:")
        print(attach_sql)
        print(f"{DRY_RUN_MSG}Enabling RLS on table {table_name}:")
        print(alter_sql)
        if not IS_DRY_RUN:
            run_query(cluster_name, attach_sql)
            run_query(cluster_name, alter_sql)
            run_query(cluster_name, alter_sql_datasharing)

    # Função principal para sincronizar RLS


def sync_rls() -> None:
    rls_rules = {}
    table_to_group: Dict[str, str] = {}
    group_members: Dict[str, List[str]] = {}  # Novo: armazena os membros de cada grupo

    for filename in glob.glob(GROUPS_PATH + "*.json"):
        print(f"Parsing file {filename}...")
        with open(filename, "r") as f:
            content = json.load(f)
            # Só processa arquivos que possuem a chave "rls"
            if "rls" in content:
                # Usa o nome do arquivo (sem extensão) como o nome do grupo
                group_name = filename.rsplit(sep="/", maxsplit=1)[1][:-5]
                print(f"--> File {filename} contains 'rls'. Processing group: {group_name}")
                group_members[group_name] = content.get("members", [])
                for table_name, rule in content["rls"].items():
                    rls_rules[table_name] = rule
                    table_to_group[table_name] = group_name
                # Cria a role e faz o grant somente para este grupo
                ensure_role_exists(group_name)
                for member in group_members[group_name]:
                    grant_role_to_user(group_name, member)
            else:
                group_name = filename.rsplit(sep="/", maxsplit=1)[1][:-5]
                print(f"--> File {filename} DOES NOT contain 'rls'. Skipping group: {group_name}")


        # Garante que para cada grupo extraído dos arquivos, a role seja criada e atribuída a todos os membros
        for group, members in group_members.items():
            ensure_role_exists(group)
            for member in members:
                grant_role_to_user(group, member)

        # Insere ou atualiza as regras na tabela rls.rls_control
        if rls_rules:
            print(f"{DRY_RUN_MSG}Syncing RLS rules from local JSON to Redshift...")
            for table_name, rule in rls_rules.items():
                column_name = rule["column"]
                parts = table_name.split(".")
                if len(parts) != 3:
                    raise ValueError(
                        f"Unexpected format for table_name: {table_name}. Expected 'schema.table.sub_table'"
                    )
                schema, table, sub_table = parts
                formatted_table_name = f'"{schema}"."{table}"."{sub_table}"'
                allowed_values = f"'{','.join(rule['accounts'])}'"
                sql_check = f"SELECT 1 FROM dev.rls.data_storage WHERE table_name = {formatted_table_name} AND column_name = '{column_name}' AND allowed_values = {allowed_values};"
                sql = f"""
                INSERT INTO dev.rls.data_storage (table_name, column_name, allowed_values)
                VALUES ({formatted_table_name}, '{column_name}', {allowed_values});
                """
                if not IS_DRY_RUN:
                    desc = run_query("prd-cluster-main", sql_check)
                    result = rs_client.get_statement_result(Id=desc.sql_id)
                    print(result)
                    if result:

                        run_query("prd-cluster-main", sql)
                else:
                    # desc = run_query("prd-cluster-main", sql_check)
                    # result = rs_client.get_statement_result(Id=desc.sql_id)
                    # print(result)
                    print(f"SQL Gerado:\n{sql}")
                    apply_rls_policies("prd-cluster-main", table_to_group)

    # Aplica as policies de RLS com base nas regras inseridas
    apply_rls_policies("prd-cluster-main", table_to_group)


if __name__ == "__main__":
    sync_rls()