import {
  CalendarDays,
  CirclePlus,
  House,
  ListChecks,
  Radar,
  Timer,
  type LucideIcon,
} from 'lucide-react'

export type PageId = 'home' | 'queue' | 'timing' | 'exposure' | 'sprint' | 'analyse' | 'scores'

type Page = {
  title: string
  icon?: LucideIcon
}

// One entry per page. TypeScript checks that every PageId has an entry.
export const pages: Record<PageId, Page> = {
  home: {
    title: 'Home',
    icon: House,
  },
  queue: {
    title: 'Priority queue',
    icon: ListChecks,
  },
  timing: {
    title: 'Exploit timing',
    icon: Timer,
  },
  exposure: {
    title: 'Structural Relationships',
    icon: Radar,
  },
  sprint: {
    title: 'Sprint plan',
    icon: CalendarDays,
  },
  analyse: {
    title: 'Add / analyse',
    icon: CirclePlus,
  },
  scores: {
    title: 'How scores work',
  },
}

// Order of the items in the main sidebar menu.
export const mainNav: PageId[] = ['home', 'queue', 'timing', 'exposure', 'sprint', 'analyse']
