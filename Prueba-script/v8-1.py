import glob
import json
import pandas as pd
import os
import re
from collections import defaultdict

######
# 20 Sep = Genera un dataset Pero:
# Crea columnas con valores númericos


# Expresión regular que identifica el formato deseado
regex = re.compile(r'Dynamic_analysis\.Droidbox\.(\w+)\.(\d+)\.\d+\.(\w+)')

def modify_dataframe_columns(df):
    new_columns = {}  # Diccionario para almacenar las nuevas columnas

    # Recorrer las columnas del DataFrame
    for column in df.columns:
        print("Nombre de la columna")
        print(column)
        match = regex.match(column)
        if match:
            # Capturar el evento (fdaccess o dexclass) y el campo final
            event = match.group(1)
            field = match.group(3)  # path, operation, etc.

            # Crear la nueva columna simplificada
            new_column = f"Dynamic_analysis.Droidbox.{event}"

            # Preservamos el valor concatenando la parte eliminada
            new_values = df[column].astype(str) + f" ({event}.{match.group(2)}.{field})"

            # Agregar los nuevos valores al diccionario
            new_columns[new_column] = new_values
        else:
            # Si la columna no coincide con la expresión, la agregamos tal cual
            new_columns[column] = df[column]

    # Concatenar todas las nuevas columnas en un solo DataFrame
    new_df = pd.concat(new_columns, axis=1)

    # Identificar las columnas originales que deben eliminarse
    columns_to_drop = [column for column in df.columns if regex.match(column)]

    # Solo eliminar las columnas si existen en el DataFrame
    columns_to_drop = [col for col in columns_to_drop if col in new_df.columns]

    # Eliminar las columnas originales que han sido simplificadas
    new_df = new_df.drop(columns=columns_to_drop, errors='ignore')  # Ignorar si no se encuentran

    # Para defragmentar el DataFrame
    new_df = new_df.copy()

    return new_df

# Configuración: número de archivos a procesar por lote
num_files_per_batch = 10

# Ruta a los archivos JSON
json_files = glob.glob("*.json")

# Ruta a los archivos CSV de Drebin
drebin_results_path = "/home/c7032681/Documents/Datasets/Drebin/drebin_results/"
drebin_files = glob.glob(os.path.join(drebin_results_path, "*.csv"))

# Cargar todos los archivos CSV de Drebin en un solo DataFrame
drebin_df = pd.concat([pd.read_csv(f, header=None) for f in drebin_files], ignore_index=True)

# Función optimizada para verificar si un APK es malware
def is_malware(apk_name, drebin_df):
    result = drebin_df[drebin_df[0] == apk_name]
    if not result.empty:
        return result[1].values[0] == 1
    return False

def flatten_json(nested_json, parent_key='', sep='.'):
    items = []
    
    if isinstance(nested_json, dict):
        for key, value in nested_json.items():
            new_key = parent_key + sep + key if parent_key else key
            if isinstance(value, dict):
                # Si el valor es un diccionario, aplanarlo recursivamente
                items.extend(flatten_json(value, new_key, sep=sep).items())
            elif isinstance(value, list):
                # Si el valor es una lista, iterar sobre sus elementos
                for i, sub_item in enumerate(value):
                    items.extend(flatten_json(sub_item, f'{new_key}[{i}]', sep=sep).items())
            else:
                # Si el valor es un tipo base, añadirlo directamente
                items.append((new_key, value))
                
    elif isinstance(nested_json, list):
        # Si el JSON es una lista desde el principio
        for i, sub_item in enumerate(nested_json):
            items.extend(flatten_json(sub_item, f'{parent_key}[{i}]', sep=sep).items())
            
    return dict(items)



# Especifica el nombre del archivo CSV en el que se acumularán los resultados
output_csv_file = "output_with_malware_filtered.csv"

# Número total de lotes
total_batches = (len(json_files) + num_files_per_batch - 1) // num_files_per_batch

# Procesar los archivos JSON en lotes
#for i in range(0, len(json_files), num_files_per_batch):
for i in range(0, 1):
    batch_files = json_files[i:i + num_files_per_batch]
    dfs = []

    for file in batch_files:
        try:
            print(f"Procesando archivo: {file}")
            with open(file) as f:
                data = json.load(f)
                apk_name = os.path.splitext(os.path.basename(file))[0]  # Nombre del archivo JSON sin la extensión
                is_mal = 1 if is_malware(apk_name, drebin_df) else 0  # Verificar si es malware

                # Si es una lista de objetos JSON
                if isinstance(data, list):
                    df = flatten_json(nested_json=data)  # pd.json_normalize(data)
                else:
                    df = flatten_json(nested_json=[data]) # pd.json_normalize([data])

                df['malware'] = is_mal  # Añadir columna malware

                # Excluir las columnas 'VirusTotal' y 'Pre_static_analysis.VT_positives'
                df = df.drop(columns=['VirusTotal', 'Pre_static_analysis.VT_positives'], errors='ignore')

                df = modify_dataframe_columns(df)
                # Verificar si el DataFrame no está vacío
                if not df.empty:
                    dfs.append(df)
                else:
                    print(f"El archivo {file} no generó datos válidos.")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error al procesar {file}: {e}")

    # Concatenar los DataFrames del lote actual si no están vacíos
    if dfs:
        batch_df = pd.concat(dfs, ignore_index=True)

        # Verificar cuántas filas se procesaron en este lote
        print(f"Filas en el lote actual: {len(batch_df)}")

        # Guardar los resultados en el archivo CSV, agregando los datos en lugar de sobrescribir
        if not batch_df.empty:
            if not os.path.isfile(output_csv_file):
                batch_df.to_csv(output_csv_file, index=False)
            else:
                batch_df.to_csv(output_csv_file, mode='a', header=False, index=False)
                
            print(f"Añadiendo {len(batch_df)} filas al CSV.")
        else:
            print(f"Ninguna fila válida en este lote {i//num_files_per_batch + 1}")
    else:
        print(f"El lote {i//num_files_per_batch + 1} no generó ningún DataFrame.")

    print(f"Procesado lote {i//num_files_per_batch + 1}/{total_batches}: {len(batch_files)} archivos JSON.")
    print(f"Resultados añadidos a {output_csv_file}")

