'use client'

import { useMemo } from 'react'
import type { ProvenanceGraph, ProvenanceNode } from '@/lib/types'

interface Props {
  graph: ProvenanceGraph
}

// Layout constants
const NODE_WIDTH = 140
const NODE_HEIGHT = 48
const H_GAP = 60    // horizontal gap between depth columns
const V_GAP = 20    // vertical gap between nodes in same column

const TYPE_ICONS: Record<string, string> = {
  dataset:   'DS',
  model:     'ML',
  transform: 'TX',
  output:    'OUT',
}

interface LayoutNode extends ProvenanceNode {
  x: number
  y: number
}

function layoutGraph(graph: ProvenanceGraph): { nodes: LayoutNode[]; width: number; height: number } {
  // Group nodes by depth
  const byDepth = new Map<number, ProvenanceNode[]>()
  for (const node of graph.nodes) {
    if (!byDepth.has(node.depth)) byDepth.set(node.depth, [])
    byDepth.get(node.depth)!.push(node)
  }

  const maxDepth = Math.max(...graph.nodes.map((n) => n.depth))
  const maxNodesPerDepth = Math.max(...Array.from(byDepth.values()).map((ns) => ns.length))

  const totalWidth = (maxDepth + 1) * (NODE_WIDTH + H_GAP) + 20
  const totalHeight = maxNodesPerDepth * (NODE_HEIGHT + V_GAP) + 40

  const layoutNodes: LayoutNode[] = []
  for (const [depth, nodes] of byDepth) {
    const colHeight = nodes.length * (NODE_HEIGHT + V_GAP) - V_GAP
    const startY = (totalHeight - colHeight) / 2
    nodes.forEach((node, i) => {
      layoutNodes.push({
        ...node,
        x: 20 + depth * (NODE_WIDTH + H_GAP),
        y: startY + i * (NODE_HEIGHT + V_GAP),
      })
    })
  }

  return { nodes: layoutNodes, width: totalWidth, height: totalHeight }
}

function getEdgePath(
  source: LayoutNode,
  target: LayoutNode,
): string {
  const sx = source.x + NODE_WIDTH
  const sy = source.y + NODE_HEIGHT / 2
  const tx = target.x
  const ty = target.y + NODE_HEIGHT / 2
  const mx = (sx + tx) / 2
  return `M ${sx} ${sy} C ${mx} ${sy}, ${mx} ${ty}, ${tx} ${ty}`
}

export function ProvenanceDAG({ graph }: Props) {
  const { nodes: layoutNodes, width, height } = useMemo(() => layoutGraph(graph), [graph])

  const nodeMap = useMemo(() => {
    const m = new Map<string, LayoutNode>()
    for (const n of layoutNodes) m.set(n.id, n)
    return m
  }, [layoutNodes])

  return (
    <div className="overflow-x-auto -mx-5 px-5">
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        aria-label="Provenance lineage graph"
        role="img"
        className="block"
        style={{ minWidth: width }}
      >
        {/* Edges */}
        {graph.edges.map((edge, i) => {
          const src = nodeMap.get(edge.source)
          const tgt = nodeMap.get(edge.target)
          if (!src || !tgt) return null
          const isContaminated = src.contaminated && tgt.contaminated
          return (
            <g key={i}>
              <path
                d={getEdgePath(src, tgt)}
                fill="none"
                stroke={isContaminated ? '#7f1d1d' : '#334155'}
                strokeWidth={isContaminated ? 2 : 1.5}
                strokeDasharray={isContaminated ? '4 3' : undefined}
                opacity={0.7}
              />
              {/* Arrow head */}
              <circle
                cx={tgt.x - 4}
                cy={tgt.y + NODE_HEIGHT / 2}
                r={3}
                fill={isContaminated ? '#ef4444' : '#475569'}
                opacity={0.7}
              />
              {/* Transform label */}
              <text
                x={(src.x + NODE_WIDTH + tgt.x) / 2}
                y={(src.y + NODE_HEIGHT / 2 + tgt.y + NODE_HEIGHT / 2) / 2 - 6}
                textAnchor="middle"
                fill="#475569"
                fontSize="9"
                fontFamily="monospace"
              >
                {edge.transformType}
              </text>
            </g>
          )
        })}

        {/* Nodes */}
        {layoutNodes.map((node) => (
          <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
            {/* Contamination glow */}
            {node.contaminated && (
              <rect
                x={-3}
                y={-3}
                width={NODE_WIDTH + 6}
                height={NODE_HEIGHT + 6}
                rx={10}
                fill="none"
                stroke="#ef4444"
                strokeWidth={1}
                opacity={0.3}
              />
            )}

            {/* Card background */}
            <rect
              width={NODE_WIDTH}
              height={NODE_HEIGHT}
              rx={8}
              fill={node.contaminated ? '#450a0a' : '#1e293b'}
              stroke={node.contaminated ? '#7f1d1d' : '#334155'}
              strokeWidth={1.5}
            />

            {/* Type badge */}
            <rect
              x={8}
              y={10}
              width={24}
              height={14}
              rx={3}
              fill={node.contaminated ? '#7f1d1d' : '#334155'}
            />
            <text
              x={20}
              y={21}
              textAnchor="middle"
              fill={node.contaminated ? '#fca5a5' : '#94a3b8'}
              fontSize="8"
              fontWeight="600"
              fontFamily="monospace"
            >
              {TYPE_ICONS[node.type] ?? 'N'}
            </text>

            {/* Label */}
            <foreignObject x={38} y={8} width={NODE_WIDTH - 46} height={NODE_HEIGHT - 16}>
              <div
                style={{
                  fontSize: '10px',
                  color: node.contaminated ? '#fca5a5' : '#e2e8f0',
                  fontWeight: 500,
                  overflow: 'hidden',
                  display: '-webkit-box',
                  WebkitLineClamp: 2,
                  WebkitBoxOrient: 'vertical',
                  lineHeight: 1.35,
                }}
              >
                {node.label}
              </div>
            </foreignObject>
          </g>
        ))}
      </svg>
    </div>
  )
}
