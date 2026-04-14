'use client'

interface Props {
  score: number  // 0–100
}

export function RiskGauge({ score }: Props) {
  const clampedScore = Math.max(0, Math.min(100, score))

  const trackColor =
    clampedScore >= 70 ? '#7f1d1d' : clampedScore >= 40 ? '#451a03' : '#052e16'

  const fillColor =
    clampedScore >= 70 ? '#ef4444' : clampedScore >= 40 ? '#f59e0b' : '#22c55e'

  const label =
    clampedScore >= 70 ? 'Critical' : clampedScore >= 40 ? 'Moderate' : 'Low'

  return (
    <div role="meter" aria-valuenow={clampedScore} aria-valuemin={0} aria-valuemax={100} aria-label={`Risk score: ${clampedScore} — ${label}`}>
      <div
        className="w-full h-2 rounded-full overflow-hidden"
        style={{ background: trackColor }}
      >
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${clampedScore}%`,
            background: fillColor,
          }}
        />
      </div>
    </div>
  )
}
