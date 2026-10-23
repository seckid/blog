// Medium profile configuration
const MEDIUM_PROFILE = 'https://medium.com/@seckid';
const MEDIUM_RSS_FEED = 'https://medium.com/feed/@seckid';

// Blog posts array (will be populated from Medium RSS)
let blogPosts = [];

// Function to fetch Medium RSS feed
async function fetchMediumPosts() {
    const blogGrid = document.getElementById('blog-posts');
    
    if (blogGrid) {
        blogGrid.innerHTML = '<p class="loading">Loading posts from Medium...</p>';
    }

    try {
        const response = await fetch('posts.json', { cache: 'no-cache' });

        if (!response.ok) {
            throw new Error('Failed to fetch posts');
        }

        const data = await response.json();
        const items = Array.isArray(data) ? data : [];

        blogPosts = items.map(item => ({
            id: item.id || '',
            title: item.title || '',
            date: item.date || '',
            category: item.category || 'Article',
            tags: Array.isArray(item.tags) ? item.tags.slice(0, 3) : [],
            excerpt: item.excerpt || '',
            link: item.link || MEDIUM_PROFILE,
            author: item.author || '',
            thumbnail: item.thumbnail || null
        }));

        blogPosts.sort((a, b) => new Date(b.date) - new Date(a.date));

        if (blogGrid) {
            renderBlogPosts();
        }
    } catch (error) {
        console.error('Error fetching Medium posts:', error);
        if (blogGrid) {
            blogGrid.innerHTML = `
                <div class="error">
                    <h3>Unable to Load Posts</h3>
                    <p>The post list could not be loaded. Please try again later.</p>
                    <p><a href="${MEDIUM_PROFILE}" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">View posts directly on Medium →</a></p>
                </div>
            `;
        }
    }
}

// Render the post cards from posts.json
function renderBlogPosts() {
    const blogGrid = document.getElementById('blog-posts');
    
    if (!blogGrid) {
        return;
    }

    if (blogPosts.length === 0) {
        blogGrid.innerHTML = `
            <div class="error">
                <p>No blog posts available.</p>
                <p><a href="${MEDIUM_PROFILE}" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">Visit Medium profile →</a></p>
            </div>
        `;
        return;
    }

    blogGrid.innerHTML = blogPosts.map(post => `
        <a href="${post.link}" target="_blank" rel="noopener noreferrer" class="blog-card">
            ${post.thumbnail ? `
                <div class="blog-card-image-wrapper">
                    <img src="${post.thumbnail}" alt="${post.title}" class="blog-card-thumbnail" loading="lazy" onerror="this.style.display='none'; this.parentElement.style.display='none';">
                </div>
            ` : ''}
            <div class="blog-card-content">
                <div class="blog-card-header">
                    <span class="blog-card-date">${formatDate(post.date)}</span>
                    <span class="blog-card-category">${post.category}</span>
                </div>
                <h3 class="blog-card-title">${post.title}</h3>
                <p class="blog-card-excerpt">${post.excerpt}</p>
                <div class="blog-card-footer">
                    ${post.tags.map(tag => `<span class="blog-card-tag">${tag}</span>`).join('')}
                </div>
                <div class="blog-card-link">
                    Read on Medium →
                </div>
            </div>
        </a>
    `).join('');
}

// Function to render individual post (redirects to Medium)
function renderPost() {
    const urlParams = new URLSearchParams(window.location.search);
    const postId = urlParams.get('id');

    if (!postId) {
        window.location.href = 'index.html';
        return;
    }

    const post = blogPosts.find(p => p.id === postId);

    if (!post) {
        document.querySelector('.post-container').innerHTML = `
            <div class="error">
                <h2>Post Not Found</h2>
                <p>The blog post you're looking for doesn't exist or hasn't been loaded yet.</p>
                <a href="index.html" class="back-link">← Back to Home</a>
            </div>
        `;
        return;
    }

    // Redirect to Medium post
    window.location.href = post.link;
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric' 
    });
}

// Initialize based on current page
document.addEventListener('DOMContentLoaded', async () => {
    if (window.location.pathname.includes('post.html')) {
        // For post pages, we need to fetch posts first to find the post
        await fetchMediumPosts();
        renderPost();
    } else {
        // For main page, fetch and display posts
        await fetchMediumPosts();
    }
});

