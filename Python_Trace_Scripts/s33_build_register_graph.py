#!/usr/bin/env python3
"""Export documented register/source relationships with the installed Graphify."""
import argparse
import json
from pathlib import Path
import networkx as nx
from graphify.cluster import cluster,score_all
from graphify.export import to_html,to_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args();out=args.directory.resolve()
    atlas=json.loads((out/'register_map.json').read_text());graph=nx.Graph()
    for record in atlas['records']:
        key=f"{record['space']}:{record['number']}";group='space:'+record['space']
        graph.add_node(group,label=record['space'],file_type='concept')
        sources=record.get('sources',[])+[s for extra in record.get('additional_documentation',[])for s in extra.get('sources',[])]
        graph.add_node(key,label=f"{record['space']} {record['number_hex']} {record['name']}",
                       file_type='register',classification=record['classification'],hardware_verified=False,
                       source_file=sources[0]['file']if sources else '',
                       source_location=str(sources[0].get('line',''))if sources else '')
        graph.add_edge(key,group,relation='namespace',confidence='EXTRACTED',weight=1.0)
        for source in sources:
            sid='source:'+source['file']
            graph.add_node(sid,label=Path(source['file']).name,file_type='document',source_file=source['file'])
            graph.add_edge(key,sid,relation='documented_or_reported_in',confidence='EXTRACTED',
                           source_location=str(source.get('line',source.get('json_pointer',''))),weight=1.0)
        if record.get('firmware_trace_record_count',0):
            node='trace:firmware_aux'
            graph.add_node(node,label=f"GNU firmware AUX traces: {len(atlas['aux_indices_with_guest_semantic_records'])} indices",file_type='evidence',
                           source_file=str(out/'evidence/firmware_aux_trace.json'))
            graph.add_edge(key,node,relation='guest_semantic_result_observed',confidence='EXTRACTED',weight=1.0)
    for family in atlas.get('computed_mmio_families',[]):
        key='computed-family:'+family['entry']
        graph.add_node(key,label='Computed store family '+family['entry'],file_type='computed_address_family',
                       classification=family['kind'],hardware_verified=False,concrete_registers_admitted=0)
        for source in family.get('sources',[]):
            sid='source:'+source['file']
            graph.add_node(sid,label=Path(source['file']).name,file_type='document',source_file=source['file'])
            graph.add_edge(key,sid,relation='formula_documented_in',confidence='EXTRACTED',weight=1.0)
    for window in atlas.get('mmio_transfer_windows',[]):
        key='mmio-window:'+window['name']
        graph.add_node(key,label='Software write window '+window['base']+' x'+str(window['element_count']),
                       file_type='mmio_write_window',classification='bounded_software_write_aperture',hardware_verified=False)
        for source in window.get('sources',[]):
            sid='source:'+source['file']
            graph.add_node(sid,label=Path(source['file']).name,file_type='document',source_file=source['file'])
            graph.add_edge(key,sid,relation='window_documented_in',confidence='EXTRACTED',weight=1.0)
    overlaps=atlas.get('mmio_window_overlaps',{})
    for pair in overlaps.get('window_pairs',[]):
        left='mmio-window:'+pair['left'];right='mmio-window:'+pair['right']
        assert left in graph and right in graph
        graph.add_edge(left,right,relation='overlapping_software_offsets',cell_count=pair['cell_count'],confidence='EXTRACTED',physical_alias_inferred=False,weight=1.0)
    for item in overlaps.get('scalar_overlaps',[]):
        left='mmio-window:'+item['window'];right='soc_mmio:'+str(int(item['address'],0))
        assert left in graph and right in graph
        graph.add_edge(left,right,relation='same_software_address_parameter_or_window',address=item['address'],confidence='EXTRACTED',physical_alias_inferred=False,weight=1.0)
    communities=cluster(graph);scores=score_all(graph,communities)
    to_json(graph,communities,str(out/'graph.json'));to_html(graph,communities,str(out/'graph.html'))
    report=['# Register source graph audit','',atlas['date'],
            'Graphify exports explicit register/source relationships, not a whole-project semantic crawl.',
            f'Nodes: {len(graph)}; edges: {graph.number_of_edges()}; communities: {len(communities)}.',
            'All edges: EXTRACTED. Documentation, static accesses and guest accesses are distinct node classifications.',
            'A documentation edge does not establish presence on Nikon hardware. No physical aliases/reset values inferred.',
            '', 'Community cohesion (raw scores):',json.dumps(scores,indent=2,default=str),'',
            'Token cost: not separately measured. This deterministic clustering/export makes no LLM calls.',
            'Hardware-verified registers: 0. Physical map remains incomplete.']
    (out/'GRAPH_REPORT.md').write_text('\n'.join(report)+'\n')
    print(len(graph),'nodes',graph.number_of_edges(),'edges',len(communities),'communities')


if __name__=='__main__':main()
