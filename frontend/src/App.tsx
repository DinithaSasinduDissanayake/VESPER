import { useState, type ComponentType } from 'react'
import { ShieldCheck } from 'lucide-react'
import { AnalysePage } from '@/analyse/AnalysePage'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { mainNav, pages, type PageId } from '@/pages'
import { ExposurePage } from '@/exposure/ExposurePage'
import { HomePage } from '@/home/HomePage'
import { SprintPlanPage } from '@/plan/SprintPlanPage'
import { QueuePage } from '@/queue/QueuePage'
import { ScoresPage } from '@/scores/ScoresPage'
import { TimingPage } from '@/timing/TimingPage'

// The component that draws each page.
const pageComponents: Record<Exclude<PageId, 'home'>, ComponentType> = {
  queue: QueuePage,
  timing: TimingPage,
  exposure: ExposurePage,
  sprint: SprintPlanPage,
  analyse: AnalysePage,
  scores: ScoresPage,
}

type NavItemProps = {
  id: PageId
  activeId: PageId
  onSelect: (id: PageId) => void
  className?: string
}

// One sidebar link. Used for the main menu and the footer link.
function NavItem({ id, activeId, onSelect, className }: NavItemProps) {
  const { title, icon: Icon } = pages[id]
  const isActive = id === activeId
  return (
    <Button
      variant="ghost"
      size="sm"
      aria-current={isActive ? 'page' : undefined}
      onClick={() => onSelect(id)}
      className={cn(
        'h-10 justify-start rounded-lg px-3 text-sidebar-foreground/80 transition-all hover:translate-x-0.5 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
        isActive && 'bg-sidebar-primary font-semibold text-sidebar-primary-foreground shadow-[0_8px_24px_-10px_oklch(0.66_0.16_250_/_85%)] hover:bg-sidebar-primary hover:text-sidebar-primary-foreground',
        className,
      )}
    >
      {Icon && <Icon />}
      {title}
    </Button>
  )
}

function App() {
  const [activeId, setActiveId] = useState<PageId>('home')
  const page = pages[activeId]
  const PageComponent = activeId === 'home' ? null : pageComponents[activeId]
  // Sidebar links and the logo all just switch the page.
  const goTo = setActiveId

  return (
    <div className="app-backdrop flex min-h-svh flex-col bg-background md:flex-row">
      <aside className="relative flex w-full shrink-0 flex-col overflow-hidden border-b border-sidebar-border bg-sidebar text-sidebar-foreground shadow-xl shadow-blue-950/10 md:w-64 md:border-r md:border-b-0">
        <div aria-hidden="true" className="pointer-events-none absolute -right-20 -top-24 size-64 rounded-full bg-blue-400/10 blur-3xl" />
        <button
          type="button"
          onClick={() => goTo('home')}
          className="flex items-center gap-3 border-b border-sidebar-border px-5 py-5 text-left"
        >
          <span className="relative grid size-10 place-items-center rounded-xl bg-gradient-to-br from-sky-300 to-blue-500 text-blue-950 shadow-lg shadow-blue-950/30 ring-1 ring-white/20">
            <ShieldCheck className="size-5" />
          </span>
          <span>
            <span className="block text-base font-bold tracking-wide text-sidebar-foreground">VESPER</span>
            <span className="mt-0.5 block text-[11px] text-white/55">
              Vulnerability evidence workbench
            </span>
          </span>
        </button>

        <nav aria-label="Main" className="flex flex-1 flex-wrap gap-1.5 p-3 md:flex-col md:flex-nowrap md:pt-5">
          {mainNav.map((id) => (
            <NavItem key={id} id={id} activeId={activeId} onSelect={goTo} />
          ))}
        </nav>

        <nav aria-label="Help" className="flex flex-col border-t border-sidebar-border p-3">
          <NavItem
            id="scores"
            activeId={activeId}
            onSelect={goTo}
            className="text-xs text-muted-foreground"
          />
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b bg-card/95 px-6 shadow-sm backdrop-blur">
          <h1 className="text-sm font-semibold text-foreground">{page.title}</h1>
          <span className="inline-flex items-center gap-2 rounded-full border border-blue-200/70 bg-white/75 px-3 py-1 text-xs font-medium text-blue-900 shadow-sm dark:border-blue-800 dark:bg-blue-950/70 dark:text-blue-100">
            <span className="size-1.5 rounded-full bg-sky-500 shadow-[0_0_0_3px_oklch(0.7_0.14_220_/_20%)]" />
            Risk intelligence
          </span>
        </header>

        {/* key resets the page's state (e.g. the open CVE) when the page changes. */}
        <main className="min-w-0 flex-1 p-3 text-sm sm:p-5 md:p-7">
          {activeId === 'home' ? (
            <HomePage key={activeId} onNavigate={goTo} />
          ) : (
            PageComponent && <PageComponent key={activeId} />
          )}
        </main>
      </div>
    </div>
  )
}

export default App
