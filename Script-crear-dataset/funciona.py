import glob
import json
import pandas as pd

###
# Convierte los json files en filas del dataset
###

json_files = glob.glob("*.json")
dfs = []

for file in json_files:
    with open(file) as f:
        data = json.load(f)  # Cargar el JSON completo
        # Si es una lista de objetos JSON
        if isinstance(data, list):
            df = pd.json_normalize(data)
        else:
            df = pd.json_normalize([data])  # Para un solo objeto JSON
            
        dfs.append(df)

# Concatenar todos los DataFrames en uno solo
final_df = pd.concat(dfs, ignore_index=True)
print(final_df)

# Especifica el nombre del archivo CSV en el que deseas guardar el DataFrame
output_csv_file = "output.csv"

# Escribe el DataFrame en el archivo CSV
final_df.to_csv(output_csv_file, index=False)

print(f"El DataFrame se ha guardado en {output_csv_file}")

