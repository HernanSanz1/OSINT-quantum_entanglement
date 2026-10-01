# Link Shield (riesgo de enlaces)

Evalúa si un enlace parece phishing, suplantación de marca o intenta ocultar su
destino, **sin visitarlo**.

## Descripción

Analiza el **texto de la URL**. No la abre, así que no deja rastro en el servidor
investigado ni te expone a su contenido. No necesita clave de API.

Señales que busca:

| Gravedad | Señal |
|---|---|
| Alta | Marca famosa en el nombre sin ser dominio oficial (`paypal-secure-login.com`, `paypal.com.evil.top`); marca imitada con números o letras de otro alfabeto (`paypa1.com`, `аpple.com`); usuario antes de la arroba (`https://banco.com@malo.com`); IP escrita como número o en hexadecimal |
| Media | Alojada en plataformas gratuitas muy usadas en phishing (`pages.dev`, `vercel.app`, `github.io`…); IP en vez de dominio; extensión de riesgo (`.xyz`, `.top`, `.click`…); nombre parecido a una marca (`robiox`); nombre de marca con otra extensión; punycode; archivo ejecutable (`.exe`, `.apk`…); correo o código largo en el enlace; varias palabras de engaño |
| Baja | Sin HTTPS; puerto raro; enlace muy largo; muchos subdominios o guiones; serie larga de números; una palabra de engaño (`login`, `verify`…); acortador |

Cada señal suma puntos (alta 50, media 20, baja 8, máximo 100):
**bajo** < 20, **medio** de 20 a 49, **alto** desde 50.

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

Probada con **300 URLs de phishing reales** (feed público de OpenPhish) y **3000 sitios
legítimos** (los más visitados según la lista Tranco):

| | Alto | Medio | Bajo |
|---|---|---|---|
| Phishing real | 9% | 67% | 25% |
| Sitios legítimos | 0% | 1% | 99% |

Es decir, marca como **medio o alto el 76% del phishing** y el **1%** de los sitios legítimos
(sobre todo páginas de plataformas gratuitas). Los acortadores se verificaron con enlaces
propios de destino conocido: el destino real coincidió en todos.

## Limitaciones

- Es una **señal, no un veredicto**: un enlace limpio puede ser malicioso. El 25% del
  phishing real pasa como "bajo" porque su URL parece normal (sitios legítimos hackeados
  o dominios nuevos con nombre corriente). Para esos casos conviene cruzarlo con
  **Domain WHOIS** (antigüedad del dominio) y **Tech Detect**.
- Las listas de marcas y de plataformas son finitas: puede haber falsos positivos con
  dominios propios de una marca que no estén en la lista oficial.
- Una página en una plataforma gratuita puede ser legítima; por eso solo sube a "medio".
