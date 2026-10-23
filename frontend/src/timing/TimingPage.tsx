// Owner: S.S.H. Thennakoon — Exploit timing page: an urgent list for the people
// who patch, and a live check of the model.
import { Fragment, useState } from 'react'
import { ExternalLink, ShieldAlert } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import { useTimingData } from './data'
import { chanceText, day, whatItIs } from './format'
import { LevelBadge, Reasons, RetrospectiveLabel } from './TimingDetail'
import { LiveTab } from './LiveTab'
import { MissingDataCard } from './TimingSection'
import type { TimingData } from './types'

// ---------------------------------------------------------------------------
// Tab 1: Urgent list
// ---------------------------------------------------------------------------

function UrgentTable({ data }: { data: TimingData }) {
  const [openId, setOpenId] = useState<string | null>(null)
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle>Patch these first</CardTitle>
        <CardDescription>
          The {data.top.length} vulnerabilities most likely to be added to CISA's list of attacked vulnerabilities
          (KEV) in the next 30 days. Click a row to see why.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10 text-right">#</TableHead>
              <TableHead>Level</TableHead>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Software</TableHead>
              <TableHead>Published</TableHead>
              <TableHead className="text-right whitespace-normal">30-day chance</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.top.map((id) => {
              const detail = data.cves.current[id]
              const open = openId === id
              return (
                <Fragment key={id}>
                  <TableRow
                    className={cn('cursor-pointer', open && 'bg-muted/50')}
                    onClick={() => setOpenId(open ? null : id)}
                    aria-expanded={open}
                  >
                    <TableCell className="text-right">{detail.rank ?? '—'}</TableCell>
                    <TableCell>
                      <LevelBadge level={detail.level} status={detail.status} />
                    </TableCell>
                    <TableCell className="font-mono">{id}</TableCell>
                    <TableCell className="w-full max-w-0 whitespace-normal" title={whatItIs(detail)}>
                      <span className="line-clamp-2 break-words">{whatItIs(detail)}</span>
                    </TableCell>
                    <TableCell>{detail.published}</TableCell>
                    <TableCell className="text-right font-medium">{chanceText(detail.raw_30d)}</TableCell>
                  </TableRow>
                  {open && (
                    <TableRow className="bg-muted/30 hover:bg-muted/30">
                      <TableCell />
                      <TableCell colSpan={5} className="whitespace-normal">
                        <div className="flex flex-col gap-2 py-1">
                          <Reasons detail={detail} />
                          <a
                            href={detail.nvd_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 self-start text-sm underline"
                          >
                            Read the full advisory on NVD <ExternalLink className="size-3.5" />
                          </a>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              )
            })}
          </TableBody>
        </Table>
        <p className="mt-2 text-sm text-muted-foreground">
          Vulnerabilities with the same score share the same number.
        </p>
      </CardContent>
    </Card>
  )
}

function AlreadyAttacked({ data }: { data: TimingData }) {
  const { recent_kev: recent } = data
  return (
    <Card className="border-red-500/40">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="size-4 text-red-600" /> Already attacked: patch these first
        </CardTitle>
        <CardDescription>
          {recent.count} vulnerabilities were added to the KEV list in the {recent.window_days} days before{' '}
          {day(data.meta.decision_time)}. They are known to be attacked, so there is nothing to predict.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ul className="flex flex-col gap-2">
          {recent.items.map((item) => (
            <li key={item.cve_id} className="flex flex-col">
              <a href={item.nvd_url} target="_blank" rel="noreferrer" className="font-mono underline">
                {item.cve_id}
              </a>
              <span>{[item.vendor, item.product].filter(Boolean).join(' ') || item.name}</span>
              <span className="text-sm text-muted-foreground">Added {item.date_added}</span>
            </li>
          ))}
        </ul>
        {recent.count > recent.items.length && (
          <p className="mt-2 text-sm text-muted-foreground">
            Showing the newest {recent.items.length} of {recent.count}.
          </p>
        )}
      </CardContent>
    </Card>
  )
}

function UrgentTab({ data }: { data: TimingData }) {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground">
        As of <strong className="text-foreground">{day(data.meta.decision_time)}</strong>. Levels:{' '}
        <strong className="text-foreground">High</strong> = top 5% of all scored vulnerabilities (
        {data.levels.counts.High.toLocaleString()}), <strong className="text-foreground">Medium</strong> = next 15%,{' '}
        <strong className="text-foreground">Low</strong> = the rest. The 30-day chance is an estimate for ranking.
      </p>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_17rem] 2xl:grid-cols-[minmax(0,1fr)_20rem]">
        <UrgentTable data={data} />
        <AlreadyAttacked data={data} />
      </div>
    </div>
  )
}

export function TimingPage() {
  const state = useTimingData()
  if (state.status === 'loading') return <p className="text-muted-foreground">Loading exploit timing…</p>
  if (state.status === 'error') return <MissingDataCard message={state.message} />
  const { data } = state

  return (
    <Tabs defaultValue="urgent" className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TabsList>
          <TabsTrigger value="urgent">Urgent list</TabsTrigger>
          <TabsTrigger value="live">Live check</TabsTrigger>
        </TabsList>
        <RetrospectiveLabel />
      </div>
      <TabsContent value="urgent">
        <UrgentTab data={data} />
      </TabsContent>
      <TabsContent value="live">
        <LiveTab />
      </TabsContent>
    </Tabs>
  )
}
