import glob # Encuentra archivos y directorios
import json # Trabaja con json
import pandas as pd
import os

###
# Convierte los json files en filas deli dataset añadiendo malware o benignware y exlcuye virus total
###


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

# Procesar los archivos JSON
json_files = glob.glob("*.json")
dfs = []

for file in json_files:
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

        dfs.append(df)

# Concatenar todos los DataFrames en uno solo
final_df = pd.concat(dfs, ignore_index=True)
print(final_df)

# Especifica el nombre del archivo CSV en el que deseas guardar el DataFrame
output_csv_file = "output_with_malware_filtered.csv"

# Escribe el DataFrame en el archivo CSV
final_df.to_csv(output_csv_file, index=False)

print(f"El DataFrame se ha guardado en {output_csv_file}")
