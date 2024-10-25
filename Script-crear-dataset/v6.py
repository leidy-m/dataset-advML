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

# Función para verificar si un archivo es malware
def is_malware(apk_name, drebin_files):
    for drebin_file in drebin_files:
        df = pd.read_csv(drebin_file, header=None)
        if apk_name in df[0].values:
            return df[df[0] == apk_name][1].values[0] == 1
    return False

# Especifica el nombre del archivo CSV en el que se acumularán los resultados
output_csv_file = "output_with_malware_filtered.csv"

# Función para hacer que los nombres de las columnas sean únicos
def make_columns_unique(df):
    df.columns = pd.Index([f"{col}.{i}" if list(df.columns).count(col) > 1 else col 
                           for i, col in enumerate(df.columns)])
    return df

# Procesar los archivos JSON en lotes
for i in range(0, len(json_files), num_files_per_batch):
    batch_files = json_files[i:i + num_files_per_batch]
    dfs = []
    columns_reference = None  # Para almacenar la estructura de columnas

    for file in batch_files:
        with open(file) as f:
            data = json.load(f)
            apk_name = os.path.splitext(os.path.basename(file))[0]  # Nombre del archivo JSON sin la extensión
            is_mal = 1 if is_malware(apk_name, drebin_files) else 0  # Verificar si es malware

            # Si es una lista de objetos JSON
            if isinstance(data, list):
                df = pd.json_normalize(data)
            else:
                df = pd.json_normalize([data])

            df['malware'] = is_mal  # Añadir columna malware

            # Excluir las columnas 'VirusTotal' y 'Pre_static_analysis.VT_positives'
            df = df.drop(columns=['VirusTotal', 'Pre_static_analysis.VT_positives'], errors='ignore')

            # Hacer que los nombres de columnas sean únicos
            df = make_columns_unique(df)

            # Si es el primer batch, se guarda la referencia de las columnas
            if columns_reference is None:
                columns_reference = df.columns
            else:
                # Asegurar que el DataFrame tenga las mismas columnas que el primer batch
                df = df.reindex(columns=columns_reference, fill_value='')

            dfs.append(df)

    # Concatenar los DataFrames del lote actual
    batch_df = pd.concat(dfs, ignore_index=True)

    # Guardar los resultados en el archivo CSV, agregando los datos en lugar de sobrescribir
    if not os.path.isfile(output_csv_file):
        batch_df.to_csv(output_csv_file, index=False)
    else:
        batch_df.to_csv(output_csv_file, mode='a', header=False, index=False)

    print(f"Procesado lote {i//num_files_per_batch + 1}: {len(batch_files)} archivos JSON.")
    print(f"Resultados añadidos a {output_csv_file}")

