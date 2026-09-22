#!/usr/bin/env python3
import os
import time

def generar_dorks(usuario, archivo_salida="dorks_personalizados.txt"):
    # Plantillas de dorks con marcador de posición para el usuario
    plantillas_dorks = [
        # BÚSQUEDA DIRECTA DEL EMAIL
        f'"{usuario}"',
        
        # PERFILES Y ACTIVIDAD EN REDES SOCIALES
        f'"{usuario}" (facebook OR twitter OR linkedin OR instagram OR github)',
        
        # DOCUMENTOS PERSONALES Y PROFESIONALES
        f'"{usuario}" (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:txt)',
        
        # HOJAS DE CÁLCULO CON DATOS PERSONALES
        f'"{usuario}" (filetype:xls OR filetype:xlsx OR filetype:csv)',
        
        # PARTICIPACIÓN EN FOROS Y COMENTARIOS
        f'"{usuario}" (forum OR comment OR discussion OR post)',
        
        # HISTORIAL DE VERSIONES Y REPOSITORIOS
        f'"{usuario}" (git OR github OR bitbucket OR svn)',
        
        # REGISTROS Y LOGS DE ACTIVIDAD
        f'"{usuario}" (log OR access_log OR error_log OR audit)',
        
        # CONTRASEÑAS Y CREDENCIALES ASOCIADAS
        f'"{usuario}" (password OR secret OR token OR key OR credential)',
        
        # ACTIVIDAD EN SITIOS DE EMPLEO
        f'"{usuario}" (linkedin OR "curriculum vitae" OR resume OR CV)',
        
        # PARTICIPACIÓN EN PROYECTOS Y COLABORACIONES
        f'"{usuario}" (project OR collaboration OR team OR contributor)',
        
        # DATOS DE CONTACTO ADICIONALES
        f'"{usuario}" (phone OR address OR contact OR location)',
        
        # INFORMACIÓN DE COMPRAS Y TRANSACCIONES
        f'"{usuario}" (purchase OR order OR transaction OR payment OR receipt)',
        
        # REGISTROS DE VIAJES Y EVENTOS
        f'"{usuario}" (travel OR event OR conference OR meeting OR flight)',
        
        # HISTORIAL MÉDICO O DE SALUD
        f'"{usuario}" (medical OR health OR doctor OR hospital OR clinic)',
        
        # ACTIVIDAD EDUCATIVA Y ACADÉMICA
        f'"{usuario}" (university OR college OR education OR degree OR thesis)',
        
        # INTERESES Y AFICIONES
        f'"{usuario}" (hobby OR interest OR passion OR favorite)',
        
        # ACTIVIDAD POLÍTICA O RELIGIOSA
        f'"{usuario}" (political OR religion OR belief OR ideology)',
        
        # HISTORIAL LEGAL O JUDICIAL
        f'"{usuario}" (court OR legal OR lawsuit OR attorney OR judge)',
        
        # FOTOS E IMÁGENES PERSONALES
        f'"{usuario}" (photo OR image OR picture OR avatar OR profile)',
        
        # REGISTROS DE VEHÍCULOS
        f'"{usuario}" (car OR vehicle OR automobile OR license OR registration)',
        
        # PROPIEDADES Y BIENES RAÍCES
        f'"{usuario}" (property OR real estate OR home OR house OR apartment)',
        
        # RELACIONES PERSONALES Y FAMILIARES
        f'"{usuario}" (family OR relative OR spouse OR child OR parent)',
        
        # HISTORIAL FINANCIERO
        f'"{usuario}" (bank OR account OR credit OR loan OR mortgage)',
        
        # ACTIVIDAD EN SITIOS DE CITAS
        f'"{usuario}" (dating OR match OR relationship OR love)',
        
        # REGISTROS DE CRIMEN O DELITOS
        f'"{usuario}" (crime OR criminal OR arrest OR warrant or police)',
        
        # HISTORIAL DE NAVEGACIÓN Y COOKIES
        f'"{usuario}" (browser OR cookie OR history OR cache OR session)',
        
        # DATOS BIOMÉTRICOS
        f'"{usuario}" (fingerprint OR iris OR face OR voice OR DNA)',
        
        # CERTIFICADOS Y CREDENCIALES PROFESIONALES
        f'"{usuario}" (certificate OR license OR degree OR diploma OR credential)',
        
        # PUBLICACIONES Y ARTÍCULOS
        f'"{usuario}" (article OR publication OR paper OR blog OR author)',
        
        # ACTIVIDAD EN SITIOS DE RESEÑAS
        f'"{usuario}" (review OR rating OR opinion OR feedback OR testimonial)',
        
        # SUSCRIPCIONES Y MEMBRESÍAS
        f'"{usuario}" (subscription OR membership OR account OR profile)',
        
        # DATOS DE UBICACIÓN Y GEOLOCALIZACIÓN
        f'"{usuario}" (location OR GPS OR coordinates OR map OR place)',
        
        # ACTIVIDAD EN JUEGOS Y ENTRETENIMIENTO
        f'"{usuario}" (game OR gaming OR play OR score OR achievement)',
        
        # HISTORIAL DE BÚSQUEDA
        f'"{usuario}" (search OR query OR browse OR find OR look up)',
        
        # REGISTROS DE VOTACIÓN
        f'"{usuario}" (vote OR election OR ballot OR poll OR referendum)',
        
        # DATOS DE SEGURO
        f'"{usuario}" (insurance OR policy OR claim OR coverage OR premium)',
        
        # HISTORIAL DE EMPLEO
        f'"{usuario}" (job OR work OR employment OR career OR occupation)',
        
        # ACTIVIDAD EN SITIOS DE SUBASTAS
        f'"{usuario}" (auction OR bid OR sale OR buy OR sell)',
        
        # REGISTROS DE INMIGRACIÓN
        f'"{usuario}" (immigration OR visa OR passport OR citizenship OR residency)',
        
        # DATOS DE SALUD MENTAL
        f'"{usuario}" (mental health OR therapy OR counseling OR psychologist OR psychiatrist)',
        
        # ACTIVIDAD EN SITIOS DE APUESTAS
        f'"{usuario}" (bet OR gamble OR casino OR lottery OR wager)',
        
        # REGISTROS DE ADOPCIÓN
        f'"{usuario}" (adoption OR foster OR guardian OR custody OR child welfare)',
        
        # DATOS DE IDENTIDAD GÉNERO
        f'"{usuario}" (gender OR identity OR orientation OR preference OR pronoun)',
        
        # ACTIVIDAD EN SITIOS DE DONACIONES
        f'"{usuario}" (donate OR charity OR contribution OR fund OR support)',
        
        # REGISTROS DE VETERANÍA
        f'"{usuario}" (veteran OR military OR service OR army OR navy)',
        
        # DATOS DE DISCAPACIDAD
        f'"{usuario}" (disability OR handicap OR impairment OR special needs OR accommodation)',
        
        # ACTIVIDAD EN SITIOS DE CONSUMO
        f'"{usuario}" (review OR rating OR consumer OR product OR service)',
        
        # REGISTROS DE TESTIMONIO
        f'"{usuario}" (testimony OR witness OR statement OR declaration OR affidavit)',
        
        # DATOS DE PENSIONES Y JUBILACIÓN
        f'"{usuario}" (pension OR retirement OR 401k OR IRA OR superannuation)',
        
        # ACTIVIDAD EN SITIOS DE NEGOCIOS
        f'"{usuario}" (business OR company OR corporation OR enterprise OR firm)',
        
        # REGISTROS DE DIVORCIO
        f'"{usuario}" (divorce OR separation OR annulment OR alimony OR child support)',
        
        # DATOS DE FALLECIMIENTO
        f'"{usuario}" (death OR deceased OR obituary OR funeral OR cemetery)',
        
        # ACTIVIDAD EN SITIOS DE VOLUNTARIADO
        f'"{usuario}" (volunteer OR donate OR charity OR nonprofit OR community)',
        
        # REGISTROS DE PATENTES
        f'"{usuario}" (patent OR invention OR intellectual property OR trademark OR copyright)',
        
        # DATOS DE INVERSIÓN
        f'"{usuario}" (investment OR stock OR bond OR mutual fund OR portfolio)',
        
        # ACTIVIDAD EN SITIOS DE COMPRAS
        f'"{usuario}" (shop OR shopping OR cart OR checkout OR order)'
    ]
    
    # Crear el archivo con los dorks personalizados
    with open(archivo_salida, 'w') as archivo:
        archivo.write(f"# Google Dorks personalizados para: {usuario}\n")
        archivo.write(f"# Generado el: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for dork in plantillas_dorks:
            archivo.write(dork + '\n')
    
    print(f"Archivo '{archivo_salida}' generado con éxito con {len(plantillas_dorks)} dorks personalizados.")
    return archivo_salida

if __name__ == "__main__":
    # Solicitar al usuario que ingrese el email o nombre de usuario a buscar
    # Se usa try/except para manejar interrupciones limpiamente
    try:
        usuario = input("Introduce el email o nombre de usuario a buscar (ej: jkav@sentinel.com.ec): ")
        if usuario:
            generar_dorks(usuario)
        else:
            print("No se introdujo ningún usuario.")
    except KeyboardInterrupt:
        print("\nOperación cancelada.")
