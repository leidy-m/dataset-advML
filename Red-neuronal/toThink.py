import pandas as pd
import numpy as np

# Ejemplo de DataFrame similar al que describes
data = pd.DataFrame({
    'Dynamic_analysis.Droidbox.dexclass.22.75992512702942.type': [1, np.nan, np.nan],
    'Dynamic_analysis.Droidbox.dexclass.22.75992512702942.path': [2, np.nan, np.nan],
    'Dynamic_analysis.Droidbox.dexclass.0.0012259483337402344.type': [3, np.nan, np.nan],
    'Dynamic_analysis.Droidbox.dexclass.0.0012259483337402344.path': [4, np.nan, np.nan],
    'Dynamic_analysis.Droidbox.fdaccess.105.68451499938965.type': [5, np.nan, np.nan],
    'Dynamic_analysis.Droidbox.fdaccess.105.68451499938965.id': [6, np.nan, np.nan]
})

# Filtrar columnas que empiezan con 'Dynamic_analysis.Droidbox.dexclass'
dexclass_cols = [col for col in data.columns if col.startswith('Dynamic_analysis.Droidbox.dexclass')]

# Crear una nueva columna para almacenar los valores combinados
data['Dynamic_analysis.Droidbox.dexclass'] = np.nan  # Inicializar la nueva columna

# Combinar los valores en la nueva columna
for col in dexclass_cols:
    # Obtener el índice de la fila donde hay un valor
    index = data[col].first_valid_index()
    if index is not None:
        value = data.at[index, col]  # Obtener el valor en la fila
        # Construir el nuevo valor para la nueva columna
        new_value = f"{value} + {col.split('.')[-1]}"  # Agregar el nombre de la columna
        data.at[index, 'Dynamic_analysis.Droidbox.dexclass'] = new_value  # Asignar el nuevo valor

# Eliminar las columnas originales
data = data.drop(columns=dexclass_cols)

# Mostrar el resultado final
print(data)
