#############################################################################
#                                                                           #
# jsonpath.py                                                               #
#                                                                           #
# Written By: Joshua Hicks (Rapid7)                                         #
# 3/31/2022                                                                 #
#                                                                           #
# Given an exported BloodHound graph in json format, this will attempt to   #
# determine the path and the required actions to go from the first item to  #
# the last or a specified target.                                           #
#                                                                           #
# For best results, the graph should start with a user and end with either  #
# a group or a computer, and there should be only one path of edges from    #
# the beginning to the end. Having multiple paths may cause issues.         #
#                                                                           # 
############################################################################# 

import json
import sys

def find_next_edge(current_edge, edges):
    # Given the current edge, finds the next edge in the path
    next_edge_source = current_edge['target']
    for edge in edges:
        if edge['source'] == next_edge_source:
            return edge

    return None

def get_node_by_id(nodes, node_id):
    # Helper function to return a node from a node_id
    for node in nodes:
        if node['id'] == node_id:
            return node

    return None

def load_json_path(filename, target_name=None):
    target = None
    with open(filename, 'r') as f:
        data = json.load(f)

    nodes = data['nodes']
    edges = data['edges']
    node_map = {}

    # Identify the user (start) node and the end (target) node
    for node in nodes:
        # Get the user (start) node
        if node['type'] == 'User':
            user = node
        # If we specified a target name, check and see if it matches the current node
        if target_name != None and node['label'].split('@')[0].lower() == target_name.lower():
            target = node
        # Otherwise we are assuming the end node is a computer
        elif node['type'] == 'Computer' and target_name == None:
            target = node
        node_map[node['id']] = node['label']
    action_path = []

    for edge in edges:
        # Find the starting edge based on the user ID
        if user['id'] == edge['source']:
            start_edge = edge
    edge_path = [start_edge]
    current_edge = start_edge
    # Conitinue identifying edges in the path until we get None returned
    while current_edge:
        current_edge = find_next_edge(current_edge, edges)
        if current_edge != None:
            edge_path.append(current_edge)
    # If at this point we still don't have a target (There were no computers, no target was specified)
    # Then go ahead and assume the last node is the target
    if target == None:
        target = get_node_by_id(nodes, edge_path[-1]['target'])
    
    # If the target is a computer, we don't want the last edge in the path
    # (It will try to add the user to the "group" that is the computer)
    if target['type'] == 'Computer':
        edge_path.pop()

    # Begin identifying the actual steps that need taken based on the path
    # steps is used for display purposes
    steps = 1
    for d in edge_path:
        # MemberOf, we can skip
        if d['etype'] == 'MemberOf':
         next
        # GenericWrite, AddMember, GenericAll, and AddSelf all imply we are adding the member to the group
        elif d['etype'] in ['GenericWrite', 'AddMember', 'GenericAll', 'AddSelf']:
            if d["target"] != target["label"]:    
                print(f'Step {steps}: Add {user["label"]} to the {node_map[d["target"]]} group')
                steps += 1
                action_path.append(['add-member', node_map[d['target']]])
        # WriteDacl implies we need to modify the group to give AddMember permissions, then go ahead and add the member
        elif d['etype'] == 'WriteDacl':
            print(f'Step {steps}: Modify DACL of group {node_map[d["target"]]} to give {user["label"]} AddMember privileges')
            steps += 1
            action_path.append(['write-dacl', node_map[d['target']]])
            print(f'Step {steps}: Add {user["label"]} to the {node_map[d["target"]]} group')
            steps += 1
            action_path.append(['add-member', node_map[d['target']]])
        # If we run into anything else, I haven't coded it up yet or it's not feasible
        else:
            print(f'Sorry, I don\'t know how to handle {d["etype"]} yet')
            return False
    # Send the data back to the main script
    return action_path, target['label'].split('.')[0], target['type']

if __name__ == "__main__":
    load_json_path(sys.argv[1])
