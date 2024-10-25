import glob
import json
import pandas as pd
import os

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

# Función para consolidar claves numéricas en un JSON
def consolidate_keys(data):
    """Consolida claves con índices numéricos en un JSON."""
    consolidated = {}

    for key, value in data.items():
        parts = key.split('.')
        base_key = '.'.join(parts[:-1])  # Parte antes del último índice
        sub_key = parts[-1]  # Última parte como clave

        # Crear la estructura si no existe
        if base_key not in consolidated:
            consolidated[base_key] = {}

        # Añadir el valor bajo la clave base
        if sub_key not in consolidated[base_key]:
            consolidated[base_key][sub_key] = []
        consolidated[base_key][sub_key].append(value)

    # Convertir listas a un solo valor si hay solo uno
    for key, sub_dict in consolidated.items():
        for sub_key, values in sub_dict.items():
            consolidated[key][sub_key] = values if len(values) > 1 else values[0]

    # Aplanar la estructura, creando una sola fila para cada clave base
    flat_data = {}
    for base_key, sub_dict in consolidated.items():
        for sub_key, value in sub_dict.items():
            # Usar una tupla para evitar duplicados en la clave
            flat_key = f"{base_key}.{sub_key}"
            flat_data[flat_key] = value

    return flat_data

# Especifica el nombre del archivo CSV en el que se acumularán los resultados
output_csv_file = "output_with_malware_filtered.csv"

# Número total de lotes
total_batches = (len(json_files) + num_files_per_batch - 1) // num_files_per_batch

# Procesar los archivos JSON en lotes
for i in range(0, len(json_files), num_files_per_batch):
    batch_files = json_files[i:i + num_files_per_batch]
    dfs = []

    for file in batch_files:
        try:
            print(f"Procesando archivo: {file}")
            with open(file) as f:
                data = json.load(f)
                apk_name = os.path.splitext(os.path.basename(file))[0]  # Nombre del archivo JSON sin la extensión
                is_mal = 1 if is_malware(apk_name, drebin_df) else 0  # Verificar si es malware

                # Consolidar claves numéricas
                data = consolidate_keys(data)

                # Convertir el diccionario consolidado en un DataFrame
                df = pd.json_normalize(data)
                df['malware'] = is_mal  # Añadir columna malware

                # Excluir las columnas 'VirusTotal' y 'Pre_static_analysis.VT_positives'
                df = df.drop(columns=['VirusTotal', 'Pre_static_analysis.VT_positives'], errors='ignore')

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

