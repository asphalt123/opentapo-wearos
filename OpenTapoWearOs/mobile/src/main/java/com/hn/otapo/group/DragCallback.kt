package com.hn.otapo.group

import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.RecyclerView

/** Drag & drop vertical + swipe-to-dismiss réutilisable pour les deux écrans groupes. */
class DragCallback(
    private val onMove: (from: Int, to: Int) -> Unit,
    private val onSwiped: ((position: Int) -> Unit)? = null,
    private val dragDirs: Int = ItemTouchHelper.UP or ItemTouchHelper.DOWN,
    private val swipeDirs: Int = 0
) : ItemTouchHelper.Callback() {

    override fun getMovementFlags(
        recyclerView: RecyclerView,
        viewHolder: RecyclerView.ViewHolder
    ): Int = makeMovementFlags(dragDirs, swipeDirs)

    override fun onMove(
        recyclerView: RecyclerView,
        viewHolder: RecyclerView.ViewHolder,
        target: RecyclerView.ViewHolder
    ): Boolean {
        onMove(viewHolder.bindingAdapterPosition, target.bindingAdapterPosition)
        return true
    }

    override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
        onSwiped?.invoke(viewHolder.bindingAdapterPosition)
    }

    override fun isLongPressDragEnabled(): Boolean = true
    override fun isItemViewSwipeEnabled(): Boolean = onSwiped != null
}
