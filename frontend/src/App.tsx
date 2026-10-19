import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { mainNav, pages, type PageId } from '@/pages'

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
      className={cn('justify-start', isActive && 'bg-sidebar-accent', className)}
    >
      {Icon && <Icon />}
      {title}
    </Button>
  )
}

function App() {
  const [activeId, setActiveId] = useState<PageId>('queue')
  const page = pages[activeId]

  return (
    <div className="flex min-h-svh">
      <aside className="flex w-64 shrink-0 flex-col border-r bg-sidebar">
        <button
          type="button"
          onClick={() => setActiveId('queue')}
          className="border-b px-4 py-3 text-left"
        >
          <span className="block font-semibold">VESPER</span>
          <span className="block text-xs text-muted-foreground">
            Vulnerability Evidence Workbench
          </span>
        </button>

        <nav aria-label="Main" className="flex flex-1 flex-col gap-1 p-2">
          {mainNav.map((id) => (
            <NavItem key={id} id={id} activeId={activeId} onSelect={setActiveId} />
          ))}
        </nav>

        <nav aria-label="Help" className="flex flex-col border-t p-2">
          <NavItem
            id="scores"
            activeId={activeId}
            onSelect={setActiveId}
            className="text-xs text-muted-foreground"
          />
        </nav>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center justify-between border-b px-6">
          <h1 className="text-sm font-semibold">{page.title}</h1>
          <span className="text-sm text-muted-foreground">Data snapshot: —</span>
        </header>

        <main className="p-6 text-sm text-muted-foreground">
          <p>{page.purpose}</p>
        </main>
      </div>
    </div>
  )
}

export default App
