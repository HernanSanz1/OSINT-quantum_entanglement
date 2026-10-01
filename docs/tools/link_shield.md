# Link Shield (riesgo de enlaces)

Evalúa si un enlace parece phishing, suplantación de marca o intenta ocultar su
destino, **sin visitarlo**.

## Descripción

Analiza el **texto de la URL**. No la abre, así que no deja rastro en el servidor
investigado ni te expone a su contenido. No necesita clave de API.

Además consulta la **antigüedad del dominio** en el registro público RDAP (el mismo que usa
Domain WHOIS). Esa consulta va al registro, **nunca al sitio investigado**.

Señales que busca:

| Gravedad | Señal |
|---|---|
| Alta | Marca famosa en el nombre sin ser dominio oficial (`paypal-secure-login.com`, `paypal.com.evil.top`); marca imitada con números o letras de otro alfabeto (`paypa1.com`, `аpple.com`); usuario antes de la arroba (`https://banco.com@malo.com`); IP escrita como número o en hexadecimal |
| Media | Alojada en plataformas gratuitas muy usadas en phishing (`pages.dev`, `vercel.app`, `github.io`…); IP en vez de dominio; extensión de riesgo (`.xyz`, `.top`, `.click`…); nombre parecido a una marca (`robiox`); nombre de marca con otra extensión; punycode; archivo ejecutable (`.exe`, `.apk`…); correo o código largo en el enlace; varias palabras de engaño |
| Baja | Sin HTTPS; puerto raro; enlace muy largo; muchos subdominios o guiones; serie larga de números; una palabra de engaño (`login`, `verify`…); acortador |

Cada señal suma puntos (alta 50, media 20, baja 8, máximo 100):
**bajo** < 20, **medio** de 20 a 49, **alto** desde 50.

### Antigüedad del dominio

| Edad | Señal |
|---|---|
| menos de 30 días | **alta**: típico de phishing y campañas nuevas |
| de 30 a 179 días | **media**: dominio joven |

Solo se consulta en dominios propios: no en IPs, acortadores, plataformas gratuitas ni
dominios oficiales de una marca. Si es un acortador, se mide el dominio del **destino final**.

### Acortadores

Solo si el enlace es de un acortador conocido (bit.ly, tinyurl.com, is.gd, t.co…) se
**siguen sus redirecciones** (máx. 5, sin descargar contenido) para ver el destino real,
y ese destino se analiza igual. A cualquier otro enlace no se le hace ninguna petición.
Se bloquean destinos locales o privados.

## Requisitos

- **Entrada obligatoria:** un dato de tipo **URL** (se acepta sin `https://`).

## Uso en SENTINEL

1. Crea un caso y añade un dato de tipo **URL**.
2. En **Herramientas**, selecciona **Link Shield** y pulsa **▶ Ejecutar Tool**.

No corre sola en Perfilamiento: necesita un enlace concreto.

## Qué devuelve

| Resultado | Categoría | Contenido |
|---|---|---|
| `Análisis de enlace: host` | Enlace | Nivel y puntuación de riesgo, dominio, destino final (si es acortador) |
| `⚠️ host: …` | Alerta | Cada señal encontrada, de más a menos grave |

## Qué tan fiable es (medido con datos reales)

Probada con **300 URLs de phishing reales** (feed público de OpenPhish, analizadas como
texto sin visitarlas), **3000 sitios legítimos** (los más visitados según Tranco) y las
**antigüedades reales** de 98 dominios de phishing y 60 legítimos consultadas por RDAP.

**Antigüedad del dominio (datos reales):**

| Edad | Dominios de phishing | Sitios legítimos |
|---|---|---|
| menos de 7 días | 33% | 0% |
| menos de 30 días | **41%** | **0%** |
| menos de 180 días | 49% | 4% |
| mediana | 267 días | 7041 días |

**Nivel de riesgo resultante:**

| | Alto | Medio | Bajo |
|---|---|---|---|
| Phishing real, solo texto de la URL | 9% | 67% | 25% |
| Phishing real, **con antigüedad** | **20%** | 65% | **16%** |
| Sitios legítimos (3000, solo texto) | 0% | 1% | 99% |
| Sitios legítimos (muestra de 60, con antigüedad) | 0% | 8% | 92% |

Es decir, marca como **medio o alto el 84% del phishing** y ningún sitio legítimo como alto.
Los acortadores se verificaron con enlaces propios de destino conocido: el destino real
coincidió en todos.

## Limitaciones

- Es una **señal, no un veredicto**: un enlace limpio puede ser malicioso. El 16% del
  phishing real aún pasa como "bajo": sitios legítimos hackeados (dominio antiguo y URL
  normal) o dominios sin datos de antigüedad.
- **Antigüedad no disponible en muchas extensiones.** El registro oficial (IANA) no publica
  RDAP para `.io`, `.co`, `.me`, `.us`, `.de`, `.es`, `.ru`, `.cn`, `.edu` y muchas más. En
  la muestra real, un 22% de los dominios de phishing y un 20% de los legítimos eran de
  esas extensiones. Cuando pasa, el resultado lo dice expresamente.
- Una página legítima nueva (una empresa recién creada) puede salir con alerta por su edad.
- Las listas de marcas y de plataformas son finitas: puede haber falsos positivos con
  dominios propios de una marca que no estén en la lista oficial.
- Una página en una plataforma gratuita puede ser legítima; por eso solo sube a "medio".
