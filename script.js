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
        // Use RSS2JSON API to convert RSS to JSON (free tier available)
        // Alternative: Use a CORS proxy or fetch directly if CORS allows
        const rss2jsonUrl = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(MEDIUM_RSS_FEED)}`;
        
        const response = await fetch(rss2jsonUrl);
        
        if (!response.ok) {
            throw new Error('Failed to fetch Medium posts');
        }
        
        const data = await response.json();
        
        if (data.status === 'ok' && data.items) {
            blogPosts = data.items.map(item => {
                // Extract date from pubDate
                const pubDate = new Date(item.pubDate);
                const dateString = pubDate.toISOString().split('T')[0];
                
                // Extract excerpt from description (remove HTML tags)
                const excerpt = stripHTML(item.description || item.content || '').substring(0, 200) + '...';
                
                // Extract category/tags from categories array
                const tags = item.categories || [];
                
                // Extract featured image - try multiple sources
                let featuredImage = null;
                
                // First, try the thumbnail field from RSS2JSON
                if (item.thumbnail) {
                    featuredImage = item.thumbnail;
                } 
                // If no thumbnail, extract first image from content/description
                else {
                    const content = item.content || item.description || '';
                    const imgMatch = content.match(/<img[^>]+src="([^"]+)"/i);
                    if (imgMatch && imgMatch[1]) {
                        featuredImage = imgMatch[1];
                    }
                    // Try alternative image formats
                    else {
                        const imgMatch2 = content.match(/<img[^>]+src='([^']+)'/i);
                        if (imgMatch2 && imgMatch2[1]) {
                            featuredImage = imgMatch2[1];
                        }
                    }
                }
                
                // Clean up Medium CDN URLs - ensure we get the full-size image
                if (featuredImage) {
                    // Medium images often have size parameters, remove them for better quality
                    featuredImage = featuredImage.replace(/[?&]w=\d+/g, '').replace(/[?&]h=\d+/g, '');
                    // Add max width parameter for better quality
                    if (featuredImage.includes('?')) {
                        featuredImage += '&w=800';
                    } else {
                        featuredImage += '?w=800';
                    }
                }
                
                return {
                    id: item.guid || item.link.split('/').pop(),
                    title: item.title,
                    date: dateString,
                    category: tags[0] || 'Article',
                    tags: tags.slice(0, 3), // Limit to 3 tags
                    excerpt: excerpt,
                    link: item.link,
                    author: item.author,
                    thumbnail: featuredImage
                };
            });
            
            // Sort by date (newest first)
            blogPosts.sort((a, b) => new Date(b.date) - new Date(a.date));
            
            if (blogGrid) {
                renderBlogPosts();
            }
        } else {
            throw new Error('Invalid RSS feed data');
        }
    } catch (error) {
        console.error('Error fetching Medium posts:', error);
        if (blogGrid) {
            blogGrid.innerHTML = `
                <div class="error">
                    <h3>Unable to Load Posts</h3>
                    <p>Could not fetch posts from Medium. Please check your connection or try again later.</p>
                    <p><a href="${MEDIUM_PROFILE}" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">View posts directly on Medium →</a></p>
                </div>
            `;
        }
    }
}

// Helper function to strip HTML tags
function stripHTML(html) {
    const tmp = document.createElement('DIV');
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || '';
}

// Function to render blog posts
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

