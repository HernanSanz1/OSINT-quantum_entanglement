#!/usr/bin/env python3
import requests
import re
import time
import json
import random
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import os
from datetime import datetime



class OSINTCollector:
    def __init__(self, profile, output_dir="osint_results"):
        """
        profile: Dictionary with keys:
            - email
            - full_name
            - company
            - role
            - location
            - domain
        """
        self.profile = profile
        self.target_user = profile.get('email', '')
        self.output_dir = output_dir
        self.session = requests.Session()
        
        # User-Agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
        ]
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        safe_name = self.profile.get('full_name', 'target').replace(' ', '_')
        self.raw_results_file = f"{output_dir}/{safe_name}_raw.json"
        self.filtered_results_file = f"{output_dir}/{safe_name}_FORENSIC_REPORT.txt"
        self.summary_file = f"{output_dir}/{safe_name}_summary.txt"
        
        self.results = {
            'profile': profile,
            'timestamp': datetime.now().isoformat(),
            'categories': {},
            'all_results': []
        }
        
    def generate_specific_queries(self):
        """Genera consultas forenses cruzando datos para máxima precisión"""
        p = self.profile
        name = p.get('full_name', '')
        # Generar variaciones de nombre (ej: "Gabriela Vaca" de "Gabriela Vaca Garzón")
        parts = name.split()
        short_name = f"{parts[0]} {parts[1]}" if len(parts) >= 2 else name
        
        email_corporate = p.get('email', '')
        email_personal = p.get('personal_email', '')
        company = p.get('company', '')
        location = p.get('location', '')
        role = p.get('role', '')
        domain = p.get('domain', '')
        phone = p.get('phone', '')
        education = p.get('education', []) # List of schools
        
        # Extract username from personal email if available
        username = email_personal.split('@')[0] if email_personal else ""
        
        queries = {
            'HIGH_PRECISION_IDENTITY': [
                f'"{name}" "{company}"',
                f'"{short_name}" "{company}"',
                f'"{name}" "{location}"',
                f'"{short_name}" "{location}"',
                f'"{name}" "{role}"',
                f'"{email_corporate}"',
                f'"{email_personal}"', # Priority search for gmail
                f'"{phone}"',          # Priority search for phone
                f'"{username}"'        # Search for pure username
            ],
            
            'USERNAME_REUSE': [
                f'site:instagram.com "{username}"',
                f'site:tiktok.com "{username}"',
                f'site:twitter.com "{username}"',
                f'site:github.com "{username}"',
                f'site:pinterest.com "{username}"',
                f'site:reddit.com "{username}"',
                f'site:telegram.me "{username}"'
            ],

            'CLEAN_EMAIL_CONTEXT': [
                f'"{email_personal}" -site:breachdirectory.org -site:spokeo.com -site:whitepages.com -site:radaris.com -site:beenverified.com -site:fastpeoplesearch.com',
                f'"{email_personal}" intext:"forum" OR intext:"foro" OR intext:"tema" OR intext:"hilo"',
                f'"{email_personal}" intext:"comentario" OR intext:"publicado" OR intext:"wrote"',
                f'site:scribd.com "{email_personal}"',
                f'site:docplayer.es "{email_personal}"',
                f'site:issuu.com "{email_personal}"'
            ],
            
            'DIGITAL_FOOTPRINT_PERSONAL': [
                f'site:instagram.com "{email_personal}"',
                f'site:facebook.com "{email_personal}"',
                f'site:twitter.com "{email_personal}"',
                f'site:linkedin.com "{email_personal}"',
                f'"{email_personal}" password OR breach OR hacked',
                f'"{email_personal}" "privacidad" OR "política"'
            ],
            
            'EDUCATION_VERIFICATION': [
                *[f'"{short_name}" "{edu}"' for edu in education],
                f'"{short_name}" "ITESM" OR "Tecnológico de Monterrey"',
                f'"{short_name}" "Universidad Internacional SEK"'
            ],
            
            'CORPORATE_FOOTPRINT': [
                f'site:{domain} "{name}"',
                f'site:{domain} "{short_name}"',
                f'site:linkedin.com "{short_name}" "{company}"',
                f'"{short_name}" "Presidente Ejecutivo" OR "Gerente" OR "CEO"',
                f'"{company}" filetype:pdf "{short_name}"'
            ],
            
            'OFFICIAL_RECORDS': [
                f'"{name}" ext:pdf OR ext:doc OR ext:xls',
                f'"{short_name}" ext:pdf OR ext:doc OR ext:xls',
                f'"{name}" intitle:"index of"',
                f'"{short_name}" (sentencia OR juicio OR legal OR decreto)',
                f'"{short_name}" "SRI" OR "Superintendencia de Compañías"'
            ],
            
            'SOCIAL_CROSS_REFERENCE': [
                f'site:facebook.com "{short_name}" "{location}"',
                f'site:twitter.com "{short_name}" "{location}"',
                f'site:instagram.com "{short_name}" "{location}"'
            ],
            
            'CONTACT_DATA': [
                f'"{short_name}" "@gmail.com" OR "@hotmail.com" OR "@yahoo.com"',
                f'"{short_name}" (telefono OR celular OR movil) "{location}"'
            ]
        }
        # Remove empty queries if fields are missing
        return queries
    
    def search_duckduckgo(self, query, max_results=10):
        self.session.headers.update({
            'User-Agent': random.choice(self.user_agents),
            'Referer': 'https://duckduckgo.com/'
        })
        
        data = {'q': query}
        url = "https://html.duckduckgo.com/html/"
        
        try:
            response = self.session.post(url, data=data)
            if response.status_code == 429:
                print("⚠️  Rate Limit Detectado. Pausando 30s...")
                time.sleep(30)
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            results = []
            
            for result in soup.select('.result'):
                try:
                    title_elem = result.select_one('.result__title')
                    snippet_elem = result.select_one('.result__snippet')
                    
                    if title_elem:
                        link_tag = title_elem.find('a')
                        if link_tag:
                            title = link_tag.get_text(strip=True)
                            link = link_tag.get('href', '')
                            snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""
                            
                            results.append({
                                'title': title,
                                'link': link,
                                'snippet': snippet,
                                'query': query
                            })
                            if len(results) >= max_results:
                                break
                except:
                    continue
            return results
        except Exception as e:
            print(f"Error: {e}")
            return []
    
    def collect_data(self):
        queries = self.generate_specific_queries()
        print(f"🕵️  Iniciando ANÁLISIS FORENSE para: {self.profile['full_name']}")
        
        for category, query_list in queries.items():
            print(f"\n📂 Categoría: {category}")
            for query in query_list:
                if not query or query.strip() == '""': continue
                
                print(f"  🔍 Buscando: {query}")
                results = self.search_duckduckgo(query)
                
                for r in results:
                    r['category'] = category # Tag result
                    self.results['all_results'].append(r)
                
                time.sleep(random.uniform(2, 5))
            
        with open(self.raw_results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        return self.results
    
    def calculate_score(self, result):
        """Asigna puntaje forense basado en coincidencias de perfil"""
        text = (result['title'] + " " + result['snippet']).lower()
        score = 0
        reasons = []
        
        p = self.profile
        # Ponderaciones
        if p.get('full_name', '').lower() in text:
            score += 10
            reasons.append("Nombre Completo")
        elif p.get('full_name', '').split()[0].lower() in text and p.get('full_name', '').split()[-1].lower() in text:
            score += 5
            reasons.append("Nombre Parcial")
            
        if p.get('email') and p['email'] in text:
            score += 20
            reasons.append("Email Corp Exacto")

        if p.get('personal_email') and p['personal_email'] in text:
            score += 30
            reasons.append("Email Personal (CRÍTICO)")
            
        if p.get('phone') and p['phone'] in text:
            score += 30
            reasons.append("Teléfono (CRÍTICO)")
            
        if p.get('company') and p['company'].lower() in text:
            score += 5
            reasons.append("Empresa")
            
        if p.get('location') and p['location'].lower() in text:
            score += 3
            reasons.append("Ubicación")
            
        if p.get('role') and p['role'].lower() in text:
            score += 3
            reasons.append("Cargo")

        # Penalizaciones por falsos positivos comunes
        negatives = ['homónimo', 'tocayo', 'linkedin.com/pub/dir'] 
        for n in negatives:
            if n in text:
                score -= 10
        
        result['forensic_score'] = score
        result['match_reasons'] = ", ".join(reasons)
        return score

    def filter_results(self):
        print("\n🧠 Analizando y puntuando resultados...")
        unique_links = {}
        
        # Deduplicar y Puntuar
        for res in self.results['all_results']:
            link = res['link']
            if link not in unique_links:
                self.calculate_score(res)
                unique_links[link] = res
            else:
                # Si ya existe, nos quedamos con la versión que tenga mejor score o mergeamos info?
                # Por simplicidad, solo actualizamos categoría si es diferente
                pass

        # Filtrar por umbral de relevancia
        sorted_results = sorted(unique_links.values(), key=lambda x: x['forensic_score'], reverse=True)
        high_confidence = [r for r in sorted_results if r['forensic_score'] >= 5]
        medium_confidence = [r for r in sorted_results if 1 <= r['forensic_score'] < 5]
        
        with open(self.filtered_results_file, 'w') as f:
            f.write(f"REPORTE FORENSE DE INTELIGENCIA (OSINT)\n")
            f.write(f"Objetivo: {self.profile['full_name']}\n")
            f.write(f"Fecha: {datetime.now()}\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"🚨 HALLAZGOS DE ALTA CONFIANZA ({len(high_confidence)})\n")
            f.write(f"(Coincidencias fuertes de nombre + empresa/cargo/ubicación)\n")
            f.write("-" * 60 + "\n")
            for r in high_confidence:
                f.write(f"[Score: {r['forensic_score']}] Motivo: {r['match_reasons']}\n")
                f.write(f"Título: {r['title']}\n")
                f.write(f"URL: {r['link']}\n")
                f.write(f"Contexto: {r['snippet']}\n\n")
                
            f.write("\n" + "="*60 + "\n")
            f.write(f"⚠️ HALLAZGOS DE MEDIA CONFIANZA ({len(medium_confidence)})\n")
            f.write(f"(Posibles coincidencias parciales, verificar manualmente)\n")
            f.write("-" * 60 + "\n")
            for r in medium_confidence:
                f.write(f"[Score: {r['forensic_score']}] Motivo: {r['match_reasons']}\n")
                f.write(f"Título: {r['title']}\n")
                f.write(f"URL: {r['link']}\n")
                f.write(f"Contexto: {r['snippet']}\n\n")

        print(f"\n✅ REPORTE GENERADO: {self.filtered_results_file}")
        print(f"   - Alta Confianza: {len(high_confidence)}")
        print(f"   - Media Confianza: {len(medium_confidence)}")

if __name__ == "__main__":
    # Perfil objetivo PERSONAL (sin filtros corporativos)
    target_profile = {
        "full_name": "Gabriela Vaca",
        "email": "gvaca@mavesa.com.ec",
        "personal_email": "gabbyvaca@gmail.com",
        "phone": "+5931800628372", # Included as personal contact
        # Vaciar campos corporativos para no sesgar
        "role": "",
        "company": "",
        "location": "Ecuador", # Generic location
        "domain": ""
    }
    
    print("Perfil Objetivo Cargado (PERSONAL DEEP DIVE):")
    print(json.dumps(target_profile, indent=2))
    
    confirm = input("\n¿Proceder con el análisis forense profundo de este perfil? (S/n): ")
    if confirm.lower() != 'n':
        collector = OSINTCollector(target_profile)
        collector.collect_data()
        collector.filter_results()

