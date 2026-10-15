# Evaluación del motor AIOps

Modelo: Isolation Forest (200 árboles) sobre 8 características por IP y ventana de 60 s,
con una envolvente de rango para valores más extremos que los vistos al entrenar.

Entrenamiento: solo tráfico normal. Prueba: 3 escenarios nuevos de 240 minutos
con ataques mezclados (datos que el modelo nunca vio). Datos generados por el simulador; en la maqueta
se repite la evaluación con logs reales de pfSense.

| Métrica | Valor |
| --- | --- |
| Ventanas evaluadas | 25405 (179 con ataque) |
| Precisión | 77.8% |
| Recall (sensibilidad) | 100.0% |
| F1 | 0.875 |
| ROC AUC | 1.0 |
| Tasa de falsos positivos | 0.20% |

Matriz de confusión:

| | Predicho normal | Predicho anomalía |
| --- | --- | --- |
| Real normal | 25175 | 51 |
| Real ataque | 0 | 179 |

Detección por tipo de ataque. "Tipo correcto" es la fracción de los detectados a los que las reglas
de clasificación les asignaron el nombre correcto:

| Tipo | Casos | Detectados | Tipo correcto |
| --- | --- | --- | --- |
| Escaneo de puertos | 29 | 100% | 100% |
| Barrido de red | 33 | 100% | 100% |
| Fuerza bruta | 20 | 100% | 100% |
| Inundación UDP | 27 | 100% | 100% |
| Inundación SYN | 38 | 100% | 100% |
| Escaneo de puertos (lento) | 32 | 100% | 100% |

Interpretación: el recall indica cuántos ataques se detectan; la precisión, cuántas alertas son
ataques reales. En las pruebas, los falsos positivos fueron ventanas de muy poca actividad (5 eventos
o menos, a menudo con un intento bloqueado) y las reglas no les asignan nombre de ataque: aparecen
como "Comportamiento inusual" o "Intentos bloqueados", fáciles de distinguir en el panel de alertas.
