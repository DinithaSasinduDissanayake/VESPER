import {
  CalendarDays,
  CirclePlus,
  ListChecks,
  Radar,
  type LucideIcon,
} from 'lucide-react'

export type PageId = 'queue' | 'exposure' | 'sprint' | 'analyse' | 'scores'

type Page = {
  title: string
  purpose: string
  icon?: LucideIcon
}

// One entry per page. TypeScript checks that every PageId has an entry.
export const pages: Record<PageId, Page> = {
  queue: {
    title: 'Priority queue',
    purpose: 'Ranked open vulnerabilities and why.',
    icon: ListChecks,
  },
  exposure: {
    title: 'Exposure',
    purpose: 'Products and vendors where risk concentrates.',
    icon: Radar,
  },
  sprint: {
    title: 'Sprint plan',
    purpose: "Which patches fit this week's engineering hours.",
    icon: CalendarDays,
  },
  analyse: {
    title: 'Add / analyse',
    purpose: 'Analyse a new vulnerability.',
    icon: CirclePlus,
  },
  scores: {
    title: 'How scores work',
    purpose: 'How the four evidence streams become one priority.',
  },
}

// Order of the items in the main sidebar menu.
export const mainNav: PageId[] = ['queue', 'exposure', 'sprint', 'analyse']
