"""
Sentinel Unified - Graph Engine
Motor de grafos para visualizar relaciones entre entidades
"""
import json
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass

from .database import db
from .models import Correlation, RelationType


@dataclass
class GraphNode:
    """Nodo del grafo"""
    id: str           # "target_1", "asset_5", "ioc_3"
    label: str        # Nombre visible
    node_type: str    # target, asset, ioc
    entity_id: int    # ID en la BD
    data: Dict        # Datos adicionales


@dataclass
class GraphEdge:
    """Arista del grafo"""
    source: str       # ID del nodo origen
    target: str       # ID del nodo destino
    relation: str     # Tipo de relacion
    confidence: int


class GraphEngine:
    """Motor de grafos para un caso"""

    def __init__(self, case_id: int):
        self.case_id = case_id
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def _node_id(self, entity_type: str, entity_id: int) -> str:
        return f"{entity_type}_{entity_id}"

    def load_from_db(self):
        """Cargar todas las entidades y correlaciones del caso"""
        # Cargar targets
        for t in db.get_targets(self.case_id):
            nid = self._node_id("target", t.id)
            self.nodes[nid] = GraphNode(
                id=nid,
                label=t.name or t.email or t.username,
                node_type="target",
                entity_id=t.id,
                data=t.to_dict()
            )

        # Cargar assets
        for a in db.get_assets(self.case_id):
            nid = self._node_id("asset", a.id)
            self.nodes[nid] = GraphNode(
                id=nid,
                label=a.value,
                node_type="asset",
                entity_id=a.id,
                data=a.to_dict()
            )

        # Cargar IOCs
        for i in db.get_iocs(self.case_id):
            nid = self._node_id("ioc", i.id)
            self.nodes[nid] = GraphNode(
                id=nid,
                label=i.value[:30] + "..." if len(i.value) > 30 else i.value,
                node_type="ioc",
                entity_id=i.id,
                data=i.to_dict()
            )

        # Cargar correlaciones
        for c in db.get_correlations(self.case_id):
            self.edges.append(GraphEdge(
                source=self._node_id(c.source_type, c.source_id),
                target=self._node_id(c.target_type, c.target_id),
                relation=c.relation_type,
                confidence=c.confidence
            ))

    def add_node(self, entity_type: str, entity_id: int, label: str, data: Dict = None):
        """Agregar nodo al grafo"""
        nid = self._node_id(entity_type, entity_id)
        if nid not in self.nodes:
            self.nodes[nid] = GraphNode(
                id=nid,
                label=label,
                node_type=entity_type,
                entity_id=entity_id,
                data=data or {}
            )

    def add_edge(self, source_type: str, source_id: int,
                 target_type: str, target_id: int,
                 relation: str, confidence: int = 50):
        """Agregar arista y persistir en BD"""
        src = self._node_id(source_type, source_id)
        tgt = self._node_id(target_type, target_id)

        # Evitar duplicados
        for e in self.edges:
            if e.source == src and e.target == tgt and e.relation == relation:
                return

        self.edges.append(GraphEdge(
            source=src,
            target=tgt,
            relation=relation,
            confidence=confidence
        ))

        # Persistir
        corr = Correlation(
            case_id=self.case_id,
            source_type=source_type,
            source_id=source_id,
            target_type=target_type,
            target_id=target_id,
            relation_type=relation,
            confidence=confidence
        )
        db.add_correlation(corr)

    def get_neighbors(self, node_id: str) -> List[Tuple[GraphNode, GraphEdge]]:
        """Obtener vecinos de un nodo"""
        neighbors = []
        for e in self.edges:
            if e.source == node_id and e.target in self.nodes:
                neighbors.append((self.nodes[e.target], e))
            elif e.target == node_id and e.source in self.nodes:
                neighbors.append((self.nodes[e.source], e))
        return neighbors

    def to_vis_js(self) -> Dict:
        """Exportar a formato vis.js para visualizacion web"""
        colors = {
            "target": "#00d4ff",   # Cyan - personas
            "asset": "#00ff66",    # Verde - infra
            "ioc": "#ff3333",      # Rojo - IOCs
        }
        shapes = {
            "target": "dot",
            "asset": "diamond",
            "ioc": "triangle",
        }

        nodes = []
        for n in self.nodes.values():
            nodes.append({
                "id": n.id,
                "label": n.label,
                "group": n.node_type,
                "color": colors.get(n.node_type, "#ffffff"),
                "shape": shapes.get(n.node_type, "dot"),
                "title": json.dumps(n.data, indent=2),
            })

        edges = []
        for e in self.edges:
            edges.append({
                "from": e.source,
                "to": e.target,
                "label": e.relation,
                "arrows": "to",
                "color": {"opacity": e.confidence / 100},
            })

        return {"nodes": nodes, "edges": edges}

    def to_pyqtgraph(self) -> Tuple[List[Dict], List[Tuple]]:
        """Exportar a formato para pyqtgraph"""
        nodes = [
            {
                "id": n.id,
                "label": n.label,
                "type": n.node_type,
                "data": n.data
            }
            for n in self.nodes.values()
        ]

        # Convertir a indices
        node_ids = list(self.nodes.keys())
        edges = []
        for e in self.edges:
            if e.source in node_ids and e.target in node_ids:
                edges.append((
                    node_ids.index(e.source),
                    node_ids.index(e.target)
                ))

        return nodes, edges

    def auto_correlate(self):
        """Auto-correlacionar entidades basado en valores comunes"""
        targets = db.get_targets(self.case_id)
        assets = db.get_assets(self.case_id)
        iocs = db.get_iocs(self.case_id)

        # Target email -> Asset domain
        for t in targets:
            if t.email and "@" in t.email:
                domain = t.email.split("@")[1]
                for a in assets:
                    if a.asset_type == "domain" and a.value == domain:
                        self.add_edge("target", t.id, "asset", a.id,
                                      RelationType.OWNS.value, 80)

        # Asset domain -> IOC domain
        for a in assets:
            if a.asset_type in ("domain", "subdomain"):
                for i in iocs:
                    if i.ioc_type == "domain" and i.value == a.value:
                        self.add_edge("asset", a.id, "ioc", i.id,
                                      RelationType.LINKED_TO.value, 90)

        # Asset IP -> IOC IP
        for a in assets:
            if a.asset_type == "ip":
                for i in iocs:
                    if i.ioc_type == "ip" and i.value == a.value:
                        self.add_edge("asset", a.id, "ioc", i.id,
                                      RelationType.LINKED_TO.value, 90)

    def stats(self) -> Dict:
        """Estadisticas del grafo"""
        type_counts = {}
        for n in self.nodes.values():
            type_counts[n.node_type] = type_counts.get(n.node_type, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes_by_type": type_counts,
        }
